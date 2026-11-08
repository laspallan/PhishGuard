"""D6: reference hashes of the protected brands' favicons, for the extension's visual check.

`python -m phishguard_ml brand-icons` fetches /favicon.ico from each brand's own domains (lexicons
BRAND_DOMAINS: legitimate sites only, never a phishing host), and writes one 64-bit difference hash
per brand to frontend/extension/src/brandHashes.json. Only the hashes are stored, not the images.

The hash must be the same here and in the extension (`frontend/extension/src/visual.ts`): the icon
is scaled to 32 x 32 RGBA (here by Pillow, there by the browser), laid on white, turned to grey
with integer weights, averaged into 9 x 8 cells, and each bit says whether a cell is darker than its
right neighbour. Both test files check the same patterns against the same hashes.
"""

import io
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx

from phishguard.services.features.lexicons import BRAND_DOMAINS

SIZE = 32
COLUMNS, ROWS = 9, 8
MAX_ICON_BYTES = 512 * 1024
OUTPUT = Path(__file__).resolve().parents[3] / "frontend" / "extension" / "src" / "brandHashes.json"


def _bounds(cell: int, cells: int) -> range:
    return range(cell * SIZE // cells, (cell + 1) * SIZE // cells)


def dhash(rgba: bytes | list[int]) -> str:
    """64-bit difference hash of a 32 x 32 RGBA image, as 16 hex characters."""
    if len(rgba) != SIZE * SIZE * 4:
        raise ValueError("expected 32 x 32 RGBA pixels")
    grey = []
    for i in range(0, len(rgba), 4):
        r, g, b, a = rgba[i : i + 4]
        r, g, b = ((c * a + 255 * (255 - a)) // 255 for c in (r, g, b))  # on white
        grey.append(r * 299 + g * 587 + b * 114)
    cells = []  # (sum, count) per cell
    for row in range(ROWS):
        for column in range(COLUMNS):
            values = [
                grey[y * SIZE + x] for y in _bounds(row, ROWS) for x in _bounds(column, COLUMNS)
            ]
            cells.append((sum(values), len(values)))
    bits = 0
    for row in range(ROWS):
        for column in range(COLUMNS - 1):
            (left, n_left), (right, n_right) = cells[
                row * COLUMNS + column : row * COLUMNS + column + 2
            ]
            bits = (bits << 1) | (left * n_right < right * n_left)  # left darker than right
    return f"{bits:016x}"


def icon_hash(content: bytes) -> str | None:
    """The hash of a favicon file, or None if it cannot be read as an image."""
    from PIL import Image, UnidentifiedImageError

    try:
        with Image.open(io.BytesIO(content)) as image:
            pixels = image.convert("RGBA").resize((SIZE, SIZE), Image.Resampling.BILINEAR)
            return dhash(pixels.tobytes())
    except (UnidentifiedImageError, OSError, ValueError):
        return None


def fetch_icon(client: httpx.Client, domain: str) -> bytes | None:
    try:
        response = client.get(f"https://{domain}/favicon.ico")
    except httpx.HTTPError:
        return None
    if response.status_code != 200 or len(response.content) > MAX_ICON_BYTES:
        return None
    return response.content


def build(client: httpx.Client, out: Path = OUTPUT) -> dict:
    brands, missing = [], []
    for brand, domains in sorted(BRAND_DOMAINS.items()):
        found = None
        for domain in sorted(domains):
            content = fetch_icon(client, domain)
            found = icon_hash(content) if content else None
            if found:
                break
        if found:
            brands.append({"brand": brand, "domains": sorted(domains), "hash": found})
        else:
            missing.append(brand)
    result = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "method": "dhash 9x8 of the 32x32 favicon, from https://<brand domain>/favicon.ico",
        "brands": brands,
        "missing": missing,
    }
    out.write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    return {"written": str(out), "brands": len(brands), "missing": missing}


def make_client() -> httpx.Client:
    return httpx.Client(
        timeout=15.0, follow_redirects=True, headers={"User-Agent": "PhishGuard research"}
    )
