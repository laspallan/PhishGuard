"""The safety rule behind D11: the API never contacts a scanned URL. Only the threat-intel
clients and the GoPhish client may open connections. The first talk to VirusTotal and OTX, the
second to the address in GOPHISH_URL, and neither to the target."""

import ast
from pathlib import Path

import phishguard.services as services

FORBIDDEN_PACKAGES = {"httpx", "httpcore", "requests", "aiohttp", "socket", "ssl", "dns", "urllib3"}
FORBIDDEN_MODULES = {"urllib.request", "http.client"}


def _imports(path: Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
            found.update(f"{node.module}.{alias.name}" for alias in node.names)
    return found


def _is_network(name: str) -> bool:
    return name.split(".")[0] in FORBIDDEN_PACKAGES or name in FORBIDDEN_MODULES


def test_the_check_recognises_network_imports(tmp_path):
    source = tmp_path / "bad.py"
    source.write_text("from urllib import request\nimport dns.resolver\n", encoding="utf-8")
    assert {n for n in _imports(source) if _is_network(n)} == {"urllib.request", "dns.resolver"}


def test_no_service_outside_intel_can_open_a_connection():
    root = Path(services.__file__).parent
    checked = 0
    for path in root.rglob("*.py"):
        relative = path.relative_to(root)
        if "intel" in relative.parts or relative.as_posix() == "simulation/gophish.py":
            continue
        checked += 1
        bad = {n for n in _imports(path) if _is_network(n)}
        assert not bad, f"{path} imports {bad}"
    assert checked > 10  # the walk really found the services
