import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
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
// A fake sbx that exits 7 shows whether a command was handed to sbx. The state
// directory holds one ready managed sandbox and one destroyed one.
async function withFakeSbx(fn: (env: NodeJS.ProcessEnv) => void): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "readonly-sbx-"));
  try {
    await writeFile(join(dir, "sbx"), "#!/bin/sh\nexit 7\n", { mode: 0o755 });
    await mkdir(join(dir, "state", "sessions"), { recursive: true });
    for (const [name, phase] of [
      ["managed-box", "ready"],
      ["old-box", "destroyed"],
    ])
      await writeFile(
        join(dir, "state", "sessions", `${name}.json`),
        JSON.stringify({ version: 2, name, agent: "claude", phase, createdAt: "" }),
      );
    fn({ ...process.env, PATH: dir, READONLY_SANDBOX_STATE_DIR: join(dir, "state") });
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
      ["sbx", "run", "claude", "/a", "--role", "OtherRole"],
      ["sbx", "run", "claude", "--network", "strict"],
      ["sbx", "run", "claude", "--name", "Not_Valid"],
      ["sbx", "run", "claude", "--name"],
      ["sbx", "run", "--name", "managed-box", "unknown-agent"],
      ["sbx", "rm", "managed-box", "other"],
      ["build", "claude", "extra"],
      ["build"],
      ["doctor", "demo"],
      ["doctor", "--agent", "claude"],
      ["launch", "claude", "demo"],
    ])
      assert.equal(cli(args, env), 1, args.join(" "));
  }),
);

test("preview reports the default or chosen sandbox name", () => {
  const preview = (...args: string[]) =>
    JSON.parse(
      spawnSync(process.execPath, ["scripts/sandbox.ts", "preview", ...args], {
        encoding: "utf8",
        env: { ...process.env, MISE_ORIGINAL_CWD: "/work/My Project" },
      }).stdout,
    ).name;
  assert.equal(preview("claude"), "claude-my-project");
  assert.equal(preview("codex", "/elsewhere/api_v2"), "codex-api-v2");
  assert.equal(preview("claude", "--name", "mine"), "mine");
});

// --name is recognized wherever it appears in the args. A managed sandbox (one
// with live launcher state) is reattached; with an agent, any other name is
// launched through the launcher; otherwise sbx handles it.
test(
  "--name reattaches managed sandboxes, names launches, and otherwise passes through",
  posixOnly,
  () =>
    withFakeSbx((env) => {
      // Intercepted: fails on the host check (no real aws/sbx here), not sbx's exit 7.
      for (const args of [
        ["run", "--name", "managed-box"],
        ["run", "--name", "managed-box", "claude"],
        ["run", "claude", "--name", "managed-box"],
        ["run", "--name=managed-box", "claude"],
        ["run", "claude", "--name", "new-box"],
        ["run", "codex", "--name=old-box"],
      ])
        assert.equal(cli(["sbx", ...args], env), 1, args.join(" "));
      for (const args of [
        ["run", "--name", "someone-else"],
        ["run", "--name", "old-box"],
      ])
        assert.equal(cli(["sbx", ...args], env), 7, args.join(" "));
    }),
);

test("unmanaged sbx commands pass through to sbx unchanged", posixOnly, () =>
  withFakeSbx((env) => {
    for (const args of [
      ["ls", "--json"],
      ["run", "--name", "someone-else"],
      ["rm", "other"],
      ["rm", "old-box"],
    ])
      assert.equal(cli(["sbx", ...args], env), 7, args.join(" "));
  }),
);
