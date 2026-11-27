"""CI and rehearsals: what three entry points of the installed depbee report for one project's
uncommitted package-lock.json change against Git HEAD, each asked as its users ask it.

    python -I .github/scripts/capture_entry_reports.py PROJECT OUT

PROJECT is a folder with package-lock.json inside a Git repository. OUT must not exist. It gets
cli.json (the report of `depbee scan PROJECT --extract`), mcp.json (the answer of the MCP server's
scan_lockfile over stdio) and dashboard.json (the run the dashboard's own server recorded for its
scan form, as history.get_run reads it back), and this run's state: the history file and a home
folder whose .cache/depbee all three use, so the two tarballs are downloaded once.
check_lodash_report.py --compare reads the three files. Needs the extract, mcp and web extras.
"""

import asyncio
import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path

# The children start as this script was started: isolated (-I) in CI and from an install.
DEPBEE = [sys.executable, *["-I"] * sys.flags.isolated, "-m", "depbee"]


async def ask_mcp(project: Path, out: Path, env: dict) -> str:
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters

    server = StdioServerParameters(command=DEPBEE[0], args=[*DEPBEE[1:], "mcp"], cwd=str(out),
                                   env=env)  # fmt: skip
    async with Client(server) as client:
        result = await client.call_tool("scan_lockfile", {"project": str(project)})
    assert not result.is_error, result.content
    (block,) = result.content
    return block.text


def ask_dashboard(project: Path, cache: Path, env: dict) -> dict:
    """Register the project, send the scan form to a dashboard server started for this and read
    the run it recorded. The dashboard registers only the folder its desktop dialog answers, which
    a runner cannot show, so the project is registered with the history API that the dialog's
    handler calls; the scan is still the form of the dashboard's own server."""
    from depbee import history

    history.register_project(project)
    (registered,) = history.list_projects()
    # --port 0: a free port, whatever listens on the default one where this runs.
    server = subprocess.Popen([*DEPBEE, "dashboard", "--port", "0", "--cache-dir", str(cache)],
                              env=env, stdout=subprocess.PIPE, text=True)  # fmt: skip
    try:
        url = server.stdout.readline().strip()  # http://127.0.0.1:<port>/
        assert re.fullmatch(r"http://127\.0\.0\.1:\d+/", url), "the dashboard did not start"
        origin = url[:-1]
        direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never a proxy
        opened = f"/projects/{registered['id']}"
        # The project's page as a browser opens it: its scan form, with the hidden fields the
        # server wrote there for this run (a form is not taken without them).
        with direct.open(origin + opened, timeout=60) as response:
            page = response.read().decode("utf-8")
        (form,) = re.findall(rf'<form method="post" action="{opened}/scans">(.*?)</form>', page, re.S)
        fields = dict(re.findall(r'<input type="hidden" name="([^"]+)" value="([^"]*)">', form))
        assert fields.get("csrf"), "the scan form has no csrf field"
        # The form's answer leads to the run (urllib follows the 303 with a GET).
        body = urllib.parse.urlencode(fields).encode("ascii")
        request = urllib.request.Request(f"{origin}{opened}/scans", body, {"Origin": origin})
        with direct.open(request, timeout=900) as response:
            landed = response.url
        # Any other address is a page that shows a result the history did not keep.
        return history.get_run(int(landed.rpartition("/runs/")[2]))
    finally:
        server.terminate()
        server.wait()


def main(project: str, out: str) -> None:
    project, out = Path(project).resolve(), Path(out).resolve()
    out.mkdir()  # new: no file an earlier run left can pass for a report of this one
    home = out / "home"
    cache = home / ".cache" / "depbee"  # where the MCP server keeps it: it has no --cache-dir
    home.mkdir()
    os.environ.update(HOME=str(home), USERPROFILE=str(home),
                      DEPBEE_HISTORY_DB=str(out / "history.sqlite3"))  # fmt: skip
    # The assets inside the installed depbee, whatever this shell or saved settings name.
    for name in ("DEPBEE_MODEL_DIR", "DEPBEE_KNOWN_MALICIOUS_DIR", "DEPBEE_CONFIG_DIR"):
        os.environ.pop(name, None)
    env = dict(os.environ)

    scanned = subprocess.run(
        [*DEPBEE, "scan", str(project), "--extract", "--cache-dir", str(cache),
         "--format", "json", "--output", str(out / "cli.json")],
        env=env, stdout=subprocess.DEVNULL)  # fmt: skip
    report = json.loads((out / "cli.json").read_bytes())
    assert scanned.returncode == report["exit_code"], (scanned.returncode, report["exit_code"])
    (out / "mcp.json").write_text(asyncio.run(ask_mcp(project, out, env)), encoding="utf-8")
    run = ask_dashboard(project, cache, env)
    (out / "dashboard.json").write_text(json.dumps(run), encoding="utf-8")
    print(f"{out}: cli.json, mcp.json, dashboard.json (run {run['id']})")


if __name__ == "__main__":
    main(*sys.argv[1:])
