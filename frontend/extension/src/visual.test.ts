import { describe, expect, it } from "vitest";

import { MATCH_BITS, dhash, faviconSource, hamming, matchBrand, ownedBy } from "./visual";

function pattern(pixel: (x: number, y: number) => [number, number, number, number]): number[] {
  const out: number[] = [];
  for (let y = 0; y < 32; y++) for (let x = 0; x < 32; x++) out.push(...pixel(x, y));
  return out;
}

const REFS = [
  { brand: "paypal", domains: ["paypal.com", "paypal.me"], hash: "3f3f3f3f3f3f3f3f" },
  { brand: "netflix", domains: ["netflix.com"], hash: "ffffffffffffffff" },
];

describe("dhash", () => {
  it("gives the same hashes as the Python reference builder (test_brand_icons.py)", () => {
    const colours = pattern((x, y) => [(x * 8) % 256, (y * 8) % 256, ((x + y) * 4) % 256, x < 4 ? 0 : 255]);
    expect(dhash(colours)).toBe("3f3f3f3f3f3f3f3f");
    const fading = pattern((x) => [255 - x * 8, 255 - x * 8, 255 - x * 8, 255]);
    expect(dhash(fading)).toBe("0000000000000000");
    const darkening = pattern((x) => [x * 8, x * 8, x * 8, 255]);
    expect(dhash(darkening)).toBe("ffffffffffffffff");
  });

  it("refuses anything but 32 x 32 RGBA", () => {
    expect(() => dhash([1, 2, 3])).toThrow();
  });
});

describe("matching", () => {
  it("counts differing bits", () => {
    expect(hamming("ffffffffffffffff", "fffffffffffffff0")).toBe(4);
    expect(hamming("0000000000000000", "0000000000000000")).toBe(0);
  });

  it("flags a brand's icon on another site, within the bit limit", () => {
    expect(matchBrand("3f3f3f3f3f3f3f3f", "paypal-login.evil-test.com", REFS)).toBe("paypal");
    expect(matchBrand("3f3f3f3f3f3f3f30", "evil-test.com", REFS)).toBe("paypal"); // 4 bits off
    expect(matchBrand("0000000000000000", "evil-test.com", REFS)).toBeNull(); // like nothing
  });

  it("never flags the brand's own domains or their subdomains", () => {
    expect(matchBrand("3f3f3f3f3f3f3f3f", "www.paypal.com", REFS)).toBeNull();
    expect(matchBrand("3f3f3f3f3f3f3f3f", "paypal.me", REFS)).toBeNull();
    expect(ownedBy("paypal.com.evil-test.com", ["paypal.com"])).toBe(false);
  });

  it("uses a limit of 8 of 64 bits", () => {
    expect(MATCH_BITS).toBe(8);
    expect(matchBrand("ffffffffffffff00", "evil-test.com", REFS)).toBe("netflix"); // 8 off
    expect(matchBrand("fffffffffffffe00", "evil-test.com", REFS)).toBeNull(); // 9 off
  });

  it("treats a shared icon as owned by every brand that uses it", () => {
    const shared = [
      { brand: "gmail", domains: ["gmail.com", "google.com"], hash: "1234123412341234" },
      { brand: "google", domains: ["google.com", "gmail.com", "youtube-test.com"], hash: "1234123412341234" },
    ];
    expect(matchBrand("1234123412341234", "youtube-test.com", shared)).toBeNull();
    expect(matchBrand("1234123412341234", "evil-test.com", shared)).toBe("gmail");
  });

  it("checks the real reference file: no two companies within the limit", async () => {
    const { brands } = (await import("./brandHashes.json")).default;
    expect(brands.length).toBeGreaterThan(0);
    for (const a of brands)
      for (const b of brands)
        if (a.hash !== b.hash) expect(hamming(a.hash, b.hash)).toBeGreaterThan(MATCH_BITS);
  });
});

describe("faviconSource", () => {
  it("never fetches a favicon from the web", () => {
    expect(faviconSource("https://evil-test.com/favicon.ico", "https://evil-test.com/", null)).toBeNull();
    expect(faviconSource("data:image/png;base64,AAAA", "https://evil-test.com/", null)).toBe(
      "data:image/png;base64,AAAA",
    );
  });

  it("uses the browser's favicon cache where there is one", () => {
    expect(faviconSource(undefined, "https://a-test.com/x", "chrome-extension://abc/")).toBe(
      "chrome-extension://abc/_favicon/?pageUrl=https%3A%2F%2Fa-test.com%2Fx&size=32",
    );
  });
});
