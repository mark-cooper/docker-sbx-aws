import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { test } from "node:test";

test("preview works with empty PATH and never executes credential_process", async () => {
  const dir = await mkdtemp(join(tmpdir(), "readonly-preview-"));
  try {
    const config = join(dir, "config"),
      credentials = join(dir, "credentials");
    await writeFile(
      config,
      "[profile demo]\nrole_arn = arn:aws:iam::222222222222:role/DeveloperRole\nsource_profile = bridge\nregion = us-west-2\n[profile bridge]\ncredential_process = should-never-execute --secret EXAMPLE_ONLY\n",
    );
    await writeFile(credentials, "");
    const result = spawnSync(process.execPath, ["scripts/sandbox.ts", "preview", "codex", "demo"], {
      cwd: resolve("."),
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: "",
        AWS_CONFIG_FILE: config,
        AWS_SHARED_CREDENTIALS_FILE: credentials,
      },
    });
    assert.equal(result.status, 0, result.stderr);
    const preview = JSON.parse(result.stdout);
    assert.equal(preview.roleArn, "arn:aws:iam::222222222222:role/ReadOnlyRole");
    assert.equal(preview.sourceProfile, "bridge");
    assert.equal(preview.workspaceMode, "empty");
    assert.equal(preview.project, null);
    assert.doesNotMatch(result.stdout, /EXAMPLE_ONLY|should-never-execute/);
    const mounted = spawnSync(
      process.execPath,
      ["scripts/sandbox.ts", "preview", "codex", "demo", "--project", dir],
      {
        cwd: resolve("."),
        encoding: "utf8",
        env: {
          ...process.env,
          PATH: "",
          AWS_CONFIG_FILE: config,
          AWS_SHARED_CREDENTIALS_FILE: credentials,
        },
      },
    );
    assert.equal(mounted.status, 0, mounted.stderr);
    assert.equal(JSON.parse(mounted.stdout).workspaceMode, "mounted");
  } finally {
    await rm(dir, { recursive: true });
  }
});
test("CLI rejects unsupported options and malformed commands", () => {
  for (const args of [
    ["launch", "unknown", "demo"],
    ["launch", "claude", "demo", "--force"],
    ["destroy", "--all"],
    ["template", "claude", "extra"],
    ["launch", "claude", "demo", "--direct"],
  ]) {
    assert.equal(
      spawnSync(process.execPath, ["scripts/sandbox.ts", ...args], { encoding: "utf8" }).status,
      1,
    );
  }
});
