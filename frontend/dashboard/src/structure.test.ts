// Enforces the feature-folder rule: shared/ never imports a feature, and a feature never
// imports another feature (anything two features need belongs in shared/).
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";

import { describe, expect, it } from "vitest";

const srcDir = join(__dirname);
const importPattern = /from\s+["']([^"']+)["']/g;

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) return sourceFiles(full);
    return /\.(ts|tsx)$/.test(name) ? [full] : [];
  });
}

function featureImports(file: string): string[] {
  const text = readFileSync(file, "utf8");
  return [...text.matchAll(importPattern)]
    .map((match) => match[1])
    .filter((spec) => spec.startsWith("@/features/") || spec.includes("/features/"))
    .map((spec) => spec.replace(/^.*features\//, "").split("/")[0]);
}

describe("folder structure", () => {
  it("shared/ does not import from features/", () => {
    const offenders = sourceFiles(join(srcDir, "shared")).filter(
      (file) => featureImports(file).length > 0,
    );

    expect(offenders.map((file) => relative(srcDir, file))).toEqual([]);
  });

  it("no feature imports another feature", () => {
    const offenders: string[] = [];
    for (const file of sourceFiles(join(srcDir, "features"))) {
      const owner = relative(join(srcDir, "features"), file).split(sep)[0];
      for (const target of featureImports(file)) {
        if (target !== owner) offenders.push(`${relative(srcDir, file)} -> ${target}`);
      }
    }

    expect(offenders).toEqual([]);
  });
});
