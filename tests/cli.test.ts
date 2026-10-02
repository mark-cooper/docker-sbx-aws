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
    const result = spawnSync(
      process.execPath,
      ["scripts/sandbox.ts", "preview", "codex", "--profile", "demo"],
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
    assert.equal(result.status, 0, result.stderr);
    const preview = JSON.parse(result.stdout);
    assert.equal(preview.roleArn, "arn:aws:iam::222222222222:role/ReadOnlyRole");
    assert.equal(preview.sourceProfile, "bridge");
    assert.equal(preview.workspaceMode, "empty");
    assert.equal(preview.project, null);
    assert.doesNotMatch(result.stdout, /EXAMPLE_ONLY|should-never-execute/);
    const mounted = spawnSync(
      process.execPath,
      ["scripts/sandbox.ts", "preview", "codex", dir, "--profile", "demo"],
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
// A fake sbx that exits 7 shows whether a command was handed to sbx.
async function withFakeSbx(fn: (env: NodeJS.ProcessEnv) => void): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "readonly-sbx-"));
  try {
    await writeFile(join(dir, "sbx"), "#!/bin/sh\nexit 7\n", { mode: 0o755 });
    fn({ ...process.env, PATH: dir });
  } finally {
    await rm(dir, { recursive: true });
  }
}
const cli = (args: string[], env: NodeJS.ProcessEnv) =>
  spawnSync(process.execPath, ["scripts/sandbox.ts", ...args], { encoding: "utf8", env }).status;

// Windows cannot spawn a shell-script sbx without a shell.
const posixOnly = { skip: process.platform === "win32" };

test("CLI rejects unsupported options and malformed commands", posixOnly, () =>
  withFakeSbx((env) => {
    for (const args of [
      ["sbx", "run", "unknown", "--profile", "demo"],
      ["sbx", "run", "claude", "--profile", "demo", "--force"],
      ["sbx", "run", "claude", "/a", "/b", "--profile", "demo"],
      ["sbx", "run", "claude", "/a"],
      ["sbx", "run", "--name", "ro-claude-0123456789ab", "codex", "extra"],
      ["sbx", "run", "--name", "ro-claude-0123456789ab", "unknown-agent"],
      ["sbx", "rm", "ro-claude-0123456789ab", "other"],
      ["build", "claude", "extra"],
      ["build"],
      ["doctor", "demo"],
      ["launch", "claude", "demo"],
    ])
      assert.equal(cli(args, env), 1, args.join(" "));
  }),
);

// --name is recognized wherever it appears in the args, and whether or not it
// names a sandbox this launcher manages; only the latter changes what happens.
test("--name is recognized regardless of position, but only a managed name is intercepted", posixOnly, () =>
  withFakeSbx((env) => {
    for (const args of [
      ["run", "--name", "ro-claude-0123456789ab"],
      ["run", "--name", "ro-claude-0123456789ab", "claude"],
      ["run", "claude", "--name", "ro-claude-0123456789ab"],
      ["run", "--name=ro-claude-0123456789ab", "claude"],
    ])
      // Intercepted: fails on the host check (no real aws/sbx here), not sbx's exit 7.
      assert.equal(cli(["sbx", ...args], env), 1, args.join(" "));
    for (const args of [["run", "--name", "someone-else"], ["run", "claude", "--name", "someone-else"]])
      assert.equal(cli(["sbx", ...args], env), 7, args.join(" "));
  }),
);

test("unmanaged sbx commands pass through to sbx unchanged", posixOnly, () =>
  withFakeSbx((env) => {
    for (const args of [
      ["ls", "--json"],
      ["run", "--name", "someone-else"],
      ["rm", "other"],
    ])
      assert.equal(cli(["sbx", ...args], env), 7, args.join(" "));
  }),
);
