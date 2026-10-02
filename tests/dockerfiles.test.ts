import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { test } from "node:test";

test("agent Dockerfiles share an identical body, differing only in their base image", async () => {
  const files = (await readdir("sandbox"))
    .filter((name) => name.startsWith("Dockerfile."))
    .sort();
  assert.ok(files.length >= 2, "expected at least two agent Dockerfiles to compare");

  const bodies = new Map<string, string>();
  for (const file of files) {
    const lines = (await readFile(`sandbox/${file}`, "utf8")).split("\n");
    const baseLine = lines.findIndex((line) => / AS base$/.test(line));
    assert.notEqual(baseLine, -1, `${file} is missing a "FROM ... AS base" line`);
    lines.splice(baseLine, 1);
    bodies.set(file, lines.join("\n"));
  }

  const [first, ...rest] = bodies.entries();
  for (const [file, body] of rest) assert.equal(body, first[1], `${file} has drifted from ${first[0]}`);
});
