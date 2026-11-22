# depbee CLI and stdio MCP server (depbee mcp). The project to check is mounted at /project.
#
#   core  depbee[mcp]. Needs no credentials; has no feature extractor (scan --extract).
#   full  the default: depbee[extract,mcp], with depbee-analyzer at the commit pyproject.toml pins.
#
#   docker build --target core -t depbee:core .
#   docker build -t depbee .                                    (analyzer repository public)
#   docker build --secret id=gh_token,env=GH_TOKEN -t depbee .  (analyzer repository private)
#
# No heredocs: on a CRLF checkout BuildKit keeps the CR in a heredoc body, which breaks sh.

# Python 3.12 on Debian trixie (Git 2.47), fixed by digest.
FROM python:3.12-slim-trixie@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS base
# git: depbee reads the base lockfile from the project's history and needs --no-lazy-fetch
# (Git 2.45), which the last command checks. libgomp1: LightGBM. No compiler, Node or npm.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git libgomp1 \
 && rm -rf /var/lib/apt/lists/* \
 && git --no-lazy-fetch version


FROM base AS build-core
WORKDIR /src
# The distribution's files, named one by one; .dockerignore admits nothing else into the context.
COPY pyproject.toml README.md ./
COPY src/depbee/ src/depbee/
# A venv without a pip of its own, filled by the base image's pip. The runtime stages copy it
# whole: an analyzer installed from a wheel instead would lose its Git provenance (PEP 610).
RUN python -m venv --without-pip /opt/depbee \
 && python -m pip --python /opt/depbee/bin/python install \
      --disable-pip-version-check --no-input --no-cache-dir ".[mcp]"


FROM base AS analyzer
# The one reviewed repository that the gh_token secret may be sent to. A literal on purpose: no
# build argument and no file of the build context can name another.
ENV ANALYZER_URL=https://github.com/26-Capstone-Project-Team01/depbee-analyzer
WORKDIR /analyzer
COPY pyproject.toml /tmp/pyproject.toml
# commit: the reviewed commit, taken from pyproject.toml, whose extract pin must be exactly this
# repository at a full commit id. mirror.git: an empty bare repository for the fetch below.
# gitconfig: read by the pip step of build-full only, the mirror in place of the repository.
RUN python -c 'import re, sys, tomllib; \
      url = sys.argv[1]; \
      extras = tomllib.load(open("/tmp/pyproject.toml", "rb"))["project"]["optional-dependencies"]; \
      pins = extras["extract"]; \
      wanted = re.escape(f"depbee-analyzer @ git+{url}@") + "([0-9a-f]{40})"; \
      pin = re.fullmatch(wanted, "\n".join(pins)); \
      pin or sys.exit(f"pyproject.toml: extract must be only depbee-analyzer @ git+{url}@<full commit id>"); \
      print(pin[1])' "$ANALYZER_URL" > commit \
 && git init --quiet --bare --initial-branch=pinned mirror.git \
 && git config --file gitconfig url.file:///analyzer/mirror.git.insteadOf "$ANALYZER_URL"
# The only step that sees the secret, and all it runs is this git fetch of that one commit: no
# pip, no build backend. The token is never in a URL, an argument, the environment, a config
# file or a layer. Git asks the helper in its own command line, which answers "get" for
# ANALYZER_URL alone (with or without .git; useHttpPath sends the path) from the secret file,
# into Git's credential pipe and nowhere else. System and user Git config are not read, so no
# other helper or store exists, no redirect is followed, only HTTPS is spoken and nothing
# prompts. The secret is optional: a public repository is fetched without it.
RUN --mount=type=secret,id=gh_token \
    GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_GLOBAL=/dev/null GIT_ALLOW_PROTOCOL=https \
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS= SSH_ASKPASS= \
    git -C mirror.git \
      -c credential.helper= \
      -c credential.helper='!f() { \
           protocol= host= path=; \
           test "$1" = get || return 0; \
           while IFS== read -r key value; do \
             case $key in protocol) protocol=$value ;; host) host=$value ;; path) path=$value ;; esac; \
           done; \
           case "$protocol://$host/$path" in "$ANALYZER_URL"|"$ANALYZER_URL.git") ;; *) return 0 ;; esac; \
           test -s /run/secrets/gh_token || return 0; \
           printf "username=x-access-token\npassword=%s\n" "$(tr -d "\r\n" < /run/secrets/gh_token)"; \
         }; f' \
      -c credential.useHttpPath=true \
      -c http.followRedirects=false \
      fetch --quiet --no-tags --depth=1 "$ANALYZER_URL" "$(cat commit):refs/heads/pinned" \
 || { if test -s /run/secrets/gh_token; \
      then echo "depbee-analyzer: not fetched although a gh_token secret was given (Git's error is above). The token must be able to read $ANALYZER_URL." >&2; \
      else echo "depbee-analyzer: not fetched, and no gh_token secret was given (Git's error is above). While $ANALYZER_URL is private, build with --secret id=gh_token,env=GH_TOKEN, or build --target core, which needs no analyzer." >&2; \
      fi; exit 1; }


FROM build-core AS build-full
COPY --from=analyzer /analyzer /analyzer
# No secret here. pip clones the URL that depbee's own metadata pins, and for this command only
# Git takes that URL from the mirror: file is the one transport allowed, so nothing but the
# fetched commit can be installed. pip never sees the rewrite and records the canonical URL and
# commit (direct_url.json), which depbee checks before it reuses extracted features.
RUN GIT_CONFIG_GLOBAL=/analyzer/gitconfig GIT_ALLOW_PROTOCOL=file GIT_TERMINAL_PROMPT=0 \
    python -m pip --python /opt/depbee/bin/python install \
      --disable-pip-version-check --no-input --no-cache-dir ".[extract,mcp]"


FROM base AS runtime
# safe.directory: the project is a bind mount owned by another user, which Git otherwise
# refuses to read. Only this one path, never a wildcard.
RUN groupadd --gid 10001 depbee \
 && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin depbee \
 && git config --system --add safe.directory /project
ENV PATH=/opt/depbee/bin:$PATH HOME=/home/depbee
WORKDIR /project
USER 10001:10001
ENTRYPOINT ["depbee"]


FROM runtime AS core
COPY --from=build-core /opt/depbee /opt/depbee


FROM runtime AS full
COPY --from=build-full /opt/depbee /opt/depbee
# Checked with the image's own interpreter and user: the analyzer is the pinned Git install with
# unchanged files, and the shipped model and index are the released ones.
RUN python -c 'import hashlib; \
      from depbee import bundled; \
      from depbee.analysis.extractor import _installed_identity; \
      identity = _installed_identity(); \
      assert identity, "depbee-analyzer is not the unchanged Git install that depbee pins"; \
      changed = [name for name, sha256 in bundled.SHA256.items() \
                 if hashlib.sha256((bundled.ROOT / name).read_bytes()).hexdigest() != sha256]; \
      assert not changed, f"not the released assets: {changed}"; \
      print(identity)'
