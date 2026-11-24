# depbee CLI, stdio MCP server (depbee mcp) and dashboard (depbee dashboard). The project the
# CLI or the MCP server checks is mounted at /project; the dashboard's projects are mounted
# under /projects (docs/docker.md).
#
#   full  the default: depbee[extract,mcp,web], with depbee-analyzer at the commit pyproject.toml
#         pins. That repository is public and pip fetches it without credentials: the build
#         takes no secret and no build argument.
#   core  depbee[mcp,web] without the feature extractor (check, scan --extract): a build that
#         fetches no Git repository, for the commands that need no analyzer.
#
#   docker build -t depbee .
#   docker build --target core -t depbee:core .
#
# No heredocs: on a CRLF checkout BuildKit keeps the CR in a heredoc body, which breaks sh.

# Node.js 24.11.0 with the npm it ships (11.6.1, the one docs/validation.md was checked with),
# fixed by digest. Only node and that npm are copied out of it, into the runtime stage.
FROM node:24.11.0-trixie-slim@sha256:a7dc5312b263c86d88b02f0665f0f4516292e3490601d3def196f6d4b8aa3f06 AS node

# Python 3.12 on Debian trixie (Git 2.47), fixed by digest.
FROM python:3.12-slim-trixie@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS base
# git: depbee reads the base lockfile from the project's history and needs --no-lazy-fetch
# (Git 2.45), which the last command checks. libgomp1: LightGBM. No compiler.
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
      --disable-pip-version-check --no-input --no-cache-dir ".[mcp,web]"


FROM build-core AS build-full
# pip clones the public URL that depbee's own metadata pins, at that commit, and records both
# (direct_url.json, PEP 610), which the full stage and every later scan check. Nothing here can
# authenticate: the build has no secret and no argument, Git reads no configuration and asks no
# one, and only HTTPS is spoken.
RUN GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_GLOBAL=/dev/null GIT_ALLOW_PROTOCOL=https \
    GIT_TERMINAL_PROMPT=0 \
    python -m pip --python /opt/depbee/bin/python install \
      --disable-pip-version-check --no-input --no-cache-dir ".[extract,mcp,web]"


FROM base AS runtime
# safe.directory: a project is a bind mount owned by another user, which Git otherwise refuses
# to read. Only the two places projects are mounted at, never every path: /project, and
# /projects with the folders below it, which are the only ones the dashboard registers.
# /projects exists so that the dashboard finds it empty, not missing, when nothing is mounted.
RUN groupadd --gid 10001 depbee \
 && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin depbee \
 && git config --system --add safe.directory /project \
 && git config --system --add safe.directory /projects \
 && git config --system --add safe.directory '/projects/*' \
 && mkdir /projects
# For the update preview and install of the dashboard and of depbee update, which run node with
# this npm-cli.js themselves (inputs.npm_cli), always with --ignore-scripts. No npm or npx
# command is put on PATH.
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
# DEPBEE_CONTAINER_PROJECTS makes depbee dashboard a container's (dashboard.mounted): it
# listens on the container's interfaces at port 5757 unless --port names another, and registers
# only folders under /projects. Publish that port to the host's 127.0.0.1 alone, same number.
ENV PATH=/opt/depbee/bin:$PATH HOME=/home/depbee DEPBEE_CONTAINER_PROJECTS=/projects
EXPOSE 5757
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
