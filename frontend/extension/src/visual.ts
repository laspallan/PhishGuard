// D6 visual-similarity check (pure logic, unit-tested). A page whose favicon looks like a protected
// brand's favicon, on a site that is not one of that brand's domains, gets a warning badge. It never
// blocks, and it is outside the 140 model features.
//
// The hash must equal ml/phishguard_ml/data/brand_icons.py: 32 x 32 RGBA laid on white, integer grey,
// 9 x 8 cell averages, one bit per "cell darker than its right neighbour". The two test files check
// the same patterns against the same hashes.

export const ICON_SIZE = 32;
const COLUMNS = 9;
const ROWS = 8;
// Bits (of 64) that may differ for a match. Below the smallest distance between two different
// companies' references (9 bits, DocuSign and Visa, brandHashes.json of 2026-11-08), so one brand's
// icon cannot match another's. Not tuned on phishing data: no stored snapshot has a favicon.
export const MATCH_BITS = 8;

export interface BrandHash {
  brand: string;
  domains: string[];
  hash: string;
}

function bounds(cell: number, cells: number): [number, number] {
  return [Math.floor((cell * ICON_SIZE) / cells), Math.floor(((cell + 1) * ICON_SIZE) / cells)];
}

/** 64-bit difference hash of 32 x 32 RGBA pixels, as 16 hex characters. */
export function dhash(rgba: ArrayLike<number>): string {
  if (rgba.length !== ICON_SIZE * ICON_SIZE * 4) throw new Error("expected 32 x 32 RGBA pixels");
  const grey: number[] = [];
  for (let i = 0; i < rgba.length; i += 4) {
    const a = rgba[i + 3];
    const [r, g, b] = [rgba[i], rgba[i + 1], rgba[i + 2]].map((c) =>
      Math.floor((c * a + 255 * (255 - a)) / 255),
    );
    grey.push(r * 299 + g * 587 + b * 114);
  }
  const cells: Array<[number, number]> = [];
  for (let row = 0; row < ROWS; row++) {
    const [y0, y1] = bounds(row, ROWS);
    for (let column = 0; column < COLUMNS; column++) {
      const [x0, x1] = bounds(column, COLUMNS);
      let sum = 0;
      for (let y = y0; y < y1; y++) for (let x = x0; x < x1; x++) sum += grey[y * ICON_SIZE + x];
      cells.push([sum, (y1 - y0) * (x1 - x0)]);
    }
  }
  let bits = "";
  for (let row = 0; row < ROWS; row++) {
    for (let column = 0; column < COLUMNS - 1; column++) {
      const [left, nLeft] = cells[row * COLUMNS + column];
      const [right, nRight] = cells[row * COLUMNS + column + 1];
      bits += left * nRight < right * nLeft ? "1" : "0";
    }
  }
  let hex = "";
  for (let i = 0; i < 64; i += 4) hex += parseInt(bits.slice(i, i + 4), 2).toString(16);
  return hex;
}

export function hamming(a: string, b: string): number {
  let distance = 0;
  for (let i = 0; i < a.length; i++) {
    let x = parseInt(a[i], 16) ^ parseInt(b[i], 16);
    while (x) {
      distance += x & 1;
      x >>= 1;
    }
  }
  return distance;
}

/** True if the host is one of the domains or a subdomain of one. */
export function ownedBy(host: string, domains: string[]): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  return domains.some((d) => h === d || h.endsWith(`.${d}`));
}

/** The brand whose favicon this looks like, if the site is not that brand's; otherwise null. */
export function matchBrand(
  hash: string,
  host: string,
  references: BrandHash[],
  maxBits: number = MATCH_BITS,
): string | null {
  const matched = references
    .map((ref) => ({ ref, bits: hamming(hash, ref.hash) }))
    .filter((m) => m.bits <= maxBits)
    .sort((a, b) => a.bits - b.bits);
  if (matched.length === 0) return null;
  // Brands of one company share an icon (Google and Gmail): any of their domains is the owner.
  const owners = matched.flatMap((m) => m.ref.domains);
  return ownedBy(host, owners) ? null : matched[0].ref.brand;
}

/**
 * Where to read the favicon without contacting the site again: a data: URL the browser already has,
 * or Chrome's and Edge's favicon cache (`_favicon`, needs the "favicon" permission). A favicon
 * address on the web is never fetched: that would contact a possible phishing host.
 */
export function faviconSource(
  favIconUrl: string | undefined,
  pageUrl: string,
  faviconCacheBase: string | null,
): string | null {
  if (favIconUrl?.startsWith("data:image/")) return favIconUrl;
  if (!faviconCacheBase) return null;
  const query = new URLSearchParams({ pageUrl, size: String(ICON_SIZE) });
  return `${faviconCacheBase.replace(/\/+$/, "")}/_favicon/?${query.toString()}`;
}
