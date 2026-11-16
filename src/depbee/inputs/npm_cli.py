"""Update preview inputs: check the project, then run npm on copies in a folder depbee made.

For the preview npm only ever runs as `--version` and `update --package-lock-only
--ignore-scripts` in that folder, never in the project: no node_modules and no lifecycle scripts.
With registry-only inputs npm 11.6.1 fetched package metadata and no tarball (docs/validation.md).
Git never runs because npm's git setting points to a file that does not exist. Only an apply with
install (clean_install) runs `npm ci --ignore-scripts` in the project itself.

Known exception (not blocked, not run): a registry package fetched during the update may depend on
a hosted Git commit (40-character sha). npm 11.6.1 then downloads that commit's tarball from the
Git host without Git into a folder under the npm cache (pacote 21.0.3 lib/git.js 43-50, 193-248,
297-310) and, if the package has build scripts or workspaces, runs `npm install --force ...
--no-package-lock-only --no-dry-run` there to prepare it (git.js 152-188, fetcher.js 98-120,
util/npm.js 4-13). The inherited npm_config_ignore_scripts=true and npm_config_git should keep
scripts and Git from running there (read in the source, not run); neither the project nor the
folder depbee made is used. npm 11 has no setting to turn this off; npm 12 blocks Git
dependencies unless --allow-git is given.
"""

import os
import re
import shutil
from pathlib import Path

from ..contracts import MAX_JSON_BYTES, GuardError, parse_json
from .git import _run

TIMEOUT_SECONDS = 120
# npm ci downloads and unpacks every tarball of the tree, not only metadata as the preview does:
# minutes for a large project on a slow link. It is the ceiling of one MCP call too.
CI_TIMEOUT_SECONDS = 600
STDOUT_LIMIT = 1024 * 1024
STDERR_LIMIT = 64 * 1024
# A large tree can print a deprecation warning per package; past the cap npm is killed mid-install.
CI_STDERR_LIMIT = 1024 * 1024
# Checked with npm 11.6.1: --no-audit drops the audit request, --no-update-notifier the version
# check and its state file; the rest keep the output plain whatever the user's settings.
FIXED_OPTIONS = (
    "--package-lock-only",
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
    "--no-update-notifier",
    "--no-progress",
    "--color=false",
    "--loglevel=warn",
)
# npm ci never writes package.json or the lockfile (lib/commands/ci.js, save: false) and with
# ignore-scripts runs no root (ci.js 102-124) or dependency script, binding.gyp included
# (@npmcli/arborist rebuild.js 150-166). The command line beats every npmrc and the environment.
CI_OPTIONS = FIXED_OPTIONS[1:]
# A target is a bare registry name: no leading "-", "." or "_" (so never an option or a path),
# ASCII only, and none of the characters a shell or cmd.exe would read (space, : \ % & | ^ < > ").
_PART = r"[A-Za-z0-9~!*'()][A-Za-z0-9._~!*'()-]*"
UPDATE_NAME = re.compile(rf"(?:@{_PART}/)?{_PART}")
MAX_NAME_LENGTH = 214
DEPENDENCY_FIELDS = ("dependencies", "devDependencies", "optionalDependencies")
LOCK_SPEC_FIELDS = (*DEPENDENCY_FIELDS, "peerDependencies")
REGISTRY_TARBALL = "https://registry.npmjs.org/"
# npm-package-arg 13 (lib/npa.js, npm 11.6.1) reads these as files even without ":" or "/": a leading "."
# (isWindowsFile, isPosixFile) or the isFileType suffix /[.](?:tgz|tar.gz|tar)$/i, whose middle
# "." is any character ("x.tarXgz"). JavaScript "$" is the end of the string here, as is "\Z".
_FILE_SUFFIX = re.compile(r"[.](?:tgz|tar.gz|tar)\Z", re.IGNORECASE)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_NPM_VERSION = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?")


def _regular_file(path: Path) -> bytes:
    if not path.is_file():
        raise GuardError(f"update needs a regular file: {path}")
    with path.open("rb") as stream:
        return stream.read(MAX_JSON_BYTES + 1)  # parse_json rejects the extra byte


def _registry_spec(spec: object) -> bool:
    """A registry version, range or tag; never Git, URL, file, link, alias or owner/repo."""
    # All of those have ":", "/" or "\", or read as a file (npm-package-arg); no control characters.
    return (
        isinstance(spec, str)
        and not any(c in spec for c in ":/\\")
        and not spec.startswith(".")
        and not _FILE_SUFFIX.search(spec)
        and not _CONTROL.search(spec)
    )


def _check_overrides(overrides: object, declared: set[str], where: str = "overrides") -> None:
    if not isinstance(overrides, dict):
        raise GuardError(f"package.json {where} must be an object")
    for key, value in overrides.items():
        if key != ".":
            # "name" or "name@range"; a scoped name starts with "@".
            scope = "@" if key.startswith("@") else ""
            name, at, selector = key[len(scope) :].partition("@")
            if not UPDATE_NAME.fullmatch(scope + name) or (at and not _registry_spec(selector)):
                raise GuardError(f"update supports only registry overrides: {where} {key}")
        if isinstance(value, dict) and key != ".":
            _check_overrides(value, declared, f"{where} {key}")
        elif not (
            value[1:] in declared  # "$name": the spec of that package.json dependency
            if isinstance(value, str) and value.startswith("$")
            else _registry_spec(value)
        ):
            raise GuardError(f"update supports only registry overrides: {where} {key}")


def read_project(project: Path) -> tuple[bytes, bytes, dict]:
    """(package.json bytes, package-lock.json bytes, package.json) of a project npm update supports.

    Refused before npm runs (GuardError): npm-shrinkwrap.json, workspaces, dependency specs and
    overrides that are not registry ranges or tags (an override may also be "$name" of a
    package.json dependency), and lock entries that are links, workspaces, have a resolved value
    outside https://registry.npmjs.org/ or a dependency spec that is not a registry range.
    """
    if not project.is_dir():
        raise GuardError(f"Project directory not found: {project}")
    if os.path.lexists(project / "npm-shrinkwrap.json"):
        raise GuardError("update does not support projects with npm-shrinkwrap.json")
    package_bytes = _regular_file(project / "package.json")
    lock_bytes = _regular_file(project / "package-lock.json")
    package, _ = parse_json(package_bytes, project / "package.json")
    lock, _ = parse_json(lock_bytes, project / "package-lock.json")
    if "workspaces" in package:
        raise GuardError("update does not support npm workspaces")
    for field in LOCK_SPEC_FIELDS:
        specs = package.get(field, {})
        if not isinstance(specs, dict):
            raise GuardError(f"package.json {field} must be an object")
        for name, spec in specs.items():
            if not _registry_spec(spec):
                raise GuardError(f"update supports only registry ranges in package.json: {name}")
    if "overrides" in package:
        # npm resolves override values while it builds the new tree, Git ones with Git.
        declared = {name for field in LOCK_SPEC_FIELDS for name in package.get(field, {})}
        _check_overrides(package["overrides"], declared)
    if type(lock.get("lockfileVersion")) is not int or lock["lockfileVersion"] not in (2, 3):
        raise GuardError("Only package-lock.json lockfileVersion 2 and 3 are supported")
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        raise GuardError("package-lock.json must contain a packages object")
    for location, entry in packages.items():
        if not isinstance(entry, dict):
            raise GuardError(f"update does not support link or workspace entries: {location}")
        for field in LOCK_SPEC_FIELDS:
            specs = entry.get(field, {})
            # npm reads these specs again while it builds the new tree.
            if not isinstance(specs, dict) or not all(map(_registry_spec, specs.values())):
                raise GuardError(
                    f"update supports only registry ranges in the lockfile: {location}"
                )
        if location == "":
            continue
        if "node_modules/" not in location or entry.get("link"):
            raise GuardError(f"update does not support link or workspace entries: {location}")
        resolved = entry.get("resolved")
        if resolved is None and entry.get("inBundle"):
            continue  # shipped inside its parent's tarball
        if not isinstance(resolved, str) or not resolved.startswith(REGISTRY_TARBALL):
            raise GuardError(
                f"update supports only {REGISTRY_TARBALL} dependencies in the lockfile: {location}"
            )
    return package_bytes, lock_bytes, package


def check_names(names: list[str], package: dict) -> None:
    """Each target must be a bare name declared in package.json; npm ignores unknown names."""
    declared = {name for field in DEPENDENCY_FIELDS for name in package.get(field, {})}
    for name in names:
        if (
            not isinstance(name, str)
            or len(name) > MAX_NAME_LENGTH
            or not UPDATE_NAME.fullmatch(name)
        ):
            raise GuardError(f"update takes package names only (no version or range): {name!r}")
        if name not in declared:
            raise GuardError(f"{name} is not a dependency in package.json")


def _npm() -> list[str]:
    """[node, npm-cli.js]: absolute paths, run without a shell (never npm.cmd or npm.ps1)."""
    windows = os.name == "nt"
    # npm.cmd passes arguments through cmd.exe and may switch to another npm under the global
    # prefix; run node.exe with the npm-cli.js installed next to it instead.
    node = shutil.which("node.exe" if windows else "node")
    if node is None or not os.path.isabs(node) or (windows and not node.lower().endswith(".exe")):
        raise GuardError(
            "node.exe not found on PATH (the current directory is not used)"
            if windows
            else "Node.js executable not found on PATH"
        )
    if windows:
        candidates = [Path(node).parent / "node_modules" / "npm" / "bin" / "npm-cli.js"]
    else:
        candidates = [
            Path(path).parent.parent / "lib" / "node_modules" / "npm" / "bin" / "npm-cli.js"
            for path in (node, os.path.realpath(node))
        ]
    for cli in candidates:
        if cli.is_file():
            return [node, str(cli)]
    raise GuardError(f"npm-cli.js not found next to {node}")


def _environment() -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.lower().startswith("npm_config_") and key.upper() != "NODE_OPTIONS"
    }
    env["npm_config_ignore_scripts"] = "true"
    return env


def _call(
    argv: list[str],
    cwd: Path,
    env: dict[str, str],
    timeout: float = TIMEOUT_SECONDS,
    stderr_limit: int = STDERR_LIMIT,
) -> tuple[int, bytes]:
    """Exit code and stdout. npm output is never put in errors: it may hold URLs or tokens."""
    try:
        code, out, _ = _run(
            argv, cwd, STDOUT_LIMIT, env,
            timeout=timeout, stderr_limit=stderr_limit, name="npm", tree=True,
        )  # fmt: skip
    except OSError as exc:
        raise GuardError(f"Unable to run npm: {exc.strerror or type(exc).__name__}") from exc
    return code, out


def _version(npm: list[str], pinned: tuple[str, ...], cwd: Path, env: dict[str, str]) -> str:
    # npm loads its config, and so searches for a workspace root, even for --version (lib/npm.js).
    code, out = _call([*npm, "--version", *pinned], cwd, env)
    version = out.decode("ascii", "replace").strip()
    if code or not _NPM_VERSION.fullmatch(version):
        raise GuardError(f"Cannot read the npm version (exit code {code})")
    return version


def update_lock(work: Path, names: list[str]) -> str:
    """Run npm update on the package.json and package-lock.json in work; return the npm version.

    work is an absolute path to a folder depbee made.
    """
    npm, env = _npm(), _environment()
    no_git = work / ".depbee-no-git" / "git"
    if not work.is_absolute() or os.path.lexists(no_git.parent):
        raise GuardError("npm needs a new, absolute work folder")
    # @npmcli/config: a CLI prefix is used as the project folder as is, and workspaces=false
    # stops the search for a workspace root above it (lib/index.js loadLocalPrefix). @npmcli/git
    # runs the git setting as the Git program (lib/which.js), so a missing file makes every Git
    # step fail; npm exports the setting to the npm it starts for a Git package (set-envs.js).
    pinned = (f"--prefix={work}", "--workspaces=false", f"--git={no_git}")
    version = _version(npm, pinned, work, env)
    code, _ = _call([*npm, "update", *FIXED_OPTIONS, *pinned, "--", *names], work, env)
    if code:
        raise GuardError(f"npm update failed with exit code {code}")
    if os.path.lexists(work / "node_modules"):
        raise GuardError("npm created node_modules during the lockfile-only update")
    return version


def clean_install(project: Path, scratch: Path) -> tuple[str, int]:
    """Run `npm ci --ignore-scripts` in project; return (npm version, npm ci exit code).

    project is the absolute project folder, checked by read_project() and without a project
    .npmrc (the caller refuses one). scratch is an absolute, new folder depbee made outside the
    project: the missing Git program and global config file are named inside it. npm ci removes
    what node_modules holds before it installs.
    """
    npm, env = _npm(), _environment()
    no_git, no_global = scratch / "no-git" / "git", scratch / "no-globalconfig" / "npmrc"
    if not (project.is_absolute() and scratch.is_absolute()) or os.path.lexists(no_git.parent):
        raise GuardError("npm needs an absolute project and a new, absolute scratch folder")
    # As in update_lock(), plus globalconfig: with a CLI prefix npm reads <prefix>/etc/npmrc as
    # the global config (@npmcli/config lib/index.js 296-312), here a file of the project.
    pinned = (
        f"--prefix={project}", "--workspaces=false", f"--git={no_git}",
        f"--globalconfig={no_global}",
    )  # fmt: skip
    version = _version(npm, pinned, project, env)
    code, _ = _call(
        [*npm, "ci", *CI_OPTIONS, *pinned], project, env, CI_TIMEOUT_SECONDS, CI_STDERR_LIMIT
    )
    return version, code
