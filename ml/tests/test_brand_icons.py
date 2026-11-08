"""D6 reference builder, offline: same hashes as the extension (visual.test.ts), no network."""

import io
import json

import httpx
import pytest

from phishguard_ml.data import brand_icons


def _pattern(pixel):
    out = []
    for y in range(32):
        for x in range(32):
            out += pixel(x, y)
    return out


def test_same_hashes_as_the_extension():
    colours = _pattern(
        lambda x, y: [x * 8 % 256, y * 8 % 256, (x + y) * 4 % 256, 0 if x < 4 else 255]
    )
    assert brand_icons.dhash(colours) == "3f3f3f3f3f3f3f3f"
    assert brand_icons.dhash(_pattern(lambda x, y: [255 - x * 8] * 3 + [255])) == "0" * 16
    assert brand_icons.dhash(_pattern(lambda x, y: [x * 8] * 3 + [255])) == "f" * 16
    with pytest.raises(ValueError):
        brand_icons.dhash([1, 2, 3])


def _png(darkening: bool) -> bytes:
    from PIL import Image

    image = Image.new("RGBA", (64, 64))
    for x in range(64):
        for y in range(64):
            v = x * 4 if darkening else 255 - x * 4
            image.putpixel((x, y), (v, v, v, 255))
    buffer = io.BytesIO()
    image.save(buffer, "PNG")
    return buffer.getvalue()


def test_build_hashes_each_brand_from_its_own_domains_only(tmp_path, monkeypatch):
    pytest.importorskip("PIL")
    monkeypatch.setattr(
        brand_icons, "BRAND_DOMAINS", {"testbank": frozenset({"testbank.example"}),
                                       "nolink": frozenset({"nolink.example"})},
    )  # fmt: skip
    seen = []

    def answer(request):
        seen.append(str(request.url))
        if request.url.host == "testbank.example":
            return httpx.Response(200, content=_png(darkening=True))
        return httpx.Response(404)

    out = tmp_path / "brandHashes.json"
    report = brand_icons.build(httpx.Client(transport=httpx.MockTransport(answer)), out)
    data = json.loads(out.read_text())
    assert report["brands"] == 1 and report["missing"] == ["nolink"]
    assert data["brands"] == [
        {"brand": "testbank", "domains": ["testbank.example"], "hash": "f" * 16}
    ]
    assert sorted(seen) == [
        "https://nolink.example/favicon.ico", "https://testbank.example/favicon.ico"
    ]  # fmt: skip


def test_unreadable_icons_are_skipped():
    pytest.importorskip("PIL")
    assert brand_icons.icon_hash(b"<svg></svg>") is None
