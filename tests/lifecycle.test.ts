import assert from "node:assert/strict";
import { mkdtemp, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { Runner, RunOptions } from "../scripts/lib/process.ts";
import type { Target } from "../scripts/lib/profiles.ts";
import {
  checkSbxVersion,
  configuration,
  destroy,
  hasGithubSecret,
  launch,
  resume,
  sbxUpgradeHint,
  unexpectedSecrets,
} from "../scripts/lib/sandbox.ts";
import { loadState, saveState } from "../scripts/lib/state.ts";

const { minSbxVersion } = (await configuration()).runtime;

const target: Target = {
  profile: "demo-project",
  sourceProfile: "team-source",
  loginProfile: "browser-session",
  account: "222222222222",
  partition: "aws",
  region: "us-west-2",
  role: "ReadOnlyRole",
  roleArn: "arn:aws:iam::222222222222:role/ReadOnlyRole",
};
type Call = { tool: string; args: string[]; options: RunOptions };

async function fixture(
  fn: (ctx: {
    project: string;
    calls: Call[];
    run: Runner;
    control: {
      denyAws: boolean;
      broadPolicy: boolean;
      injectFails: boolean;
      createFails: boolean;
      secrets: { scope: string; type: string; name: string }[];
    };
  }) => Promise<void>,
) {
  const dir = await mkdtemp(join(tmpdir(), "readonly-lifecycle-"));
  const project = await realpath(dir),
    previous = process.env.READONLY_SANDBOX_STATE_DIR;
  process.env.READONLY_SANDBOX_STATE_DIR = join(dir, "state");
  const calls: Call[] = [],
    control = {
      denyAws: false,
      broadPolicy: false,
      injectFails: false,
      createFails: false,
      secrets: [] as { scope: string; type: string; name: string }[],
    };
  let name = "",
    mounted = false,
    identity = {};
  // Sandbox-scoped allows the launcher has added, as sbx would record them.
  const sandboxAllows = new Set<string>();
  const run: Runner = async (tool, args, options = {}) => {
    calls.push({ tool, args, options });
    let result: unknown = "";
    let code = 0;
    if (tool === "aws") {
      if (args[0] === "--version") result = "aws-cli/2.35.9";
      else if (args[1] === "assume-role") {
        if (control.denyAws) return { code: 1, stdout: "EXAMPLE_SECRET", stderr: "denied" };
        const session = args[args.indexOf("--role-session-name") + 1];
        identity = {
          Account: target.account,
          Arn: `arn:aws:sts::${target.account}:assumed-role/ReadOnlyRole/${session}`,
          UserId: `AROEXAMPLE:${session}`,
        };
        result = {
          Credentials: {
            AccessKeyId: "ASIA_EXAMPLE_ONLY",
            SecretAccessKey: "EXAMPLE_SECRET",
            SessionToken: "EXAMPLE_TOKEN",
            Expiration: new Date(Date.now() + 3600_000).toISOString(),
          },
          AssumedRoleUser: {
            Arn: (identity as { Arn: string }).Arn,
            AssumedRoleId: (identity as { UserId: string }).UserId,
          },
        };
      } else
        result = args.includes("--profile")
          ? { Account: "111111111111", Arn: "source", UserId: "source-id" }
          : identity;
    } else if (args[0] === "version") result = `sbx version: v${minSbxVersion} test`;
    else if (args[0] === "mcp") result = { servers: [] };
    else if (args[0] === "secret") result = { secrets: control.secrets, custom_secrets: [] };
    else if (args[0] === "settings")
      result = args[2] === "ssh.agentForwardingEnabled" ? "false" : "";
    else if (args[0] === "create") {
      if (control.createFails) code = 1;
      else {
        name = args[args.indexOf("--name") + 1];
        mounted = args.includes(project);
      }
    } else if (args[0] === "ls") result = { sandboxes: name ? [{ name, status: "stopped" }] : [] };
    else if (args[0] === "inspect")
      result = {
        name,
        agent: "claude",
        runtime_mounts: [],
        workspace: mounted ? "/home/agent/workspace" : undefined,
      };
    else if (args[0] === "policy" && args[1] === "allow") sandboxAllows.add(args.at(-1)!);
    else if (args[0] === "policy" && args[1] === "ls")
      result = {
        rules: control.broadPolicy
          ? [
              {
                resource_type: "network",
                status: "active",
                decision: "allow",
                actions: ["net:connect:tcp"],
                resources: ["**"],
              },
            ]
          : args[2] === name
            ? [...sandboxAllows].map((resource) => ({
                resource_type: "network",
                status: "active",
                decision: "allow",
                actions: ["net:connect:tcp"],
                resources: [resource],
                applies_to: `sandbox:${name}`,
              }))
            : [],
      };
    else if (args[0] === "policy" && args[1] === "check") {
      // Like the reviewed sbx version: a denial prints its decision and exits 1.
      // Independent of the launcher's matcher: sbx "**." admits the domain and
      // any subdomain on the same port.
      const probe = args.at(-1)!;
      const allowed = [...sandboxAllows].some(
        (rule) =>
          rule === probe ||
          (rule.startsWith("**.") &&
            (probe === rule.slice(3) || probe.endsWith(`.${rule.slice(3)}`))),
      );
      result = { allowed, target: args.at(-1) };
      if (!allowed) code = 1;
    } else if (args[0] === "exec") {
      const command = args.at(-1);
      if (command === "check") result = { cwd: "/home/agent/workspace", home: "/home/agent" };
      else if (command === "inject") {
        result = { identity };
        if (control.injectFails) code = 1;
      } else result = "blocked";
    }
    return {
      code,
      stdout: typeof result === "string" ? result : JSON.stringify(result),
      stderr: "",
    };
  };
  try {
    await fn({ project, calls, run, control });
  } finally {
    if (previous === undefined) delete process.env.READONLY_SANDBOX_STATE_DIR;
    else process.env.READONLY_SANDBOX_STATE_DIR = previous;
    await rm(dir, { recursive: true });
  }
}
test("launch orders checks before handoff, keeps secrets on stdin, and mounts the project", async () =>
  fixture(async ({ project, run, calls }) => {
    const name = await launch(target, { agent: "claude", project }, run);
    const create = calls.find((c) => c.args[0] === "create")!;
    assert.ok(create.args.includes(project));
    assert.ok(create.args.includes("--skills"));
    assert.ok(create.args.includes("--static-mcp="));
    const inject = calls.find((c) => c.args.at(-1) === "inject")!;
    assert.equal(JSON.parse(inject.options.input!).credentials.SecretAccessKey, "EXAMPLE_SECRET");
    assert.ok(inject.args.includes("-i"));
    assert.ok(
      calls.findIndex((c) => c.args.at(-1) === "probe-network") <
        calls.findIndex((c) => c.args[1] === "assume-role"),
    );
    assert.ok(
      calls.findIndex((c) => c.args.at(-1) === "inject") <
        calls.findIndex((c) => c.args[0] === "run"),
    );
    assert.ok(!JSON.stringify(calls.map((c) => c.args)).includes("EXAMPLE_SECRET"));
    for (const call of calls.filter((c) => c.tool === "sbx"))
      assert.equal(call.options.env?.AWS_ACCESS_KEY_ID, undefined);
    const state = await loadState(name);
    assert.equal(state.phase, "ready");
    assert.doesNotMatch(JSON.stringify(state), /EXAMPLE_SECRET|EXAMPLE_TOKEN/);
    await destroy(name, run);
    assert.equal((await loadState(name)).phase, "destroyed");
  }));
test("broad host policy stops before creating a sandbox or contacting AWS STS", async () =>
  fixture(async ({ project, run, calls, control }) => {
    control.broadPolicy = true;
    await assert.rejects(launch(target, { agent: "claude", project }, run), /outside/);
    assert.ok(!calls.some((c) => c.args[0] === "create" || c.args[0] === "sts"));
  }));
test("denied assumption and failed in-VM verification never start an agent", async () => {
  for (const failure of ["denyAws", "injectFails"] as const)
    await fixture(async ({ project, run, calls, control }) => {
      control[failure] = true;
      await assert.rejects(launch(target, { agent: "claude", project }, run));
      assert.ok(!calls.some((c) => c.args[0] === "run"));
      assert.ok(calls.some((c) => c.args[0] === "stop"));
      assert.ok(
        calls.filter((c) => c.tool === "aws").every((c) => !c.args.includes(target.profile)),
      );
    });
});
test("project mode mounts only explicitly selected project; destruction never deletes host files", async () =>
  fixture(async ({ project, run, calls }) => {
    const name = await launch(target, { agent: "claude", project }, run);
    assert.ok(calls.find((c) => c.args[0] === "create")!.args.includes(project));
    assert.ok(!calls.some((c) => c.args[0] === "bundle" && c.args[1] === "create"));
    await destroy(name, run);
    assert.ok((await readdir(project)).includes("state"));
  }));
test("legacy clone sessions cannot be destroyed by the new launcher", async () =>
  fixture(async ({ project, run, calls }) => {
    const name = await launch(target, { agent: "claude", project }, run);
    const state = await loadState(name);
    await writeFile(
      join(process.env.READONLY_SANDBOX_STATE_DIR!, "sessions", `${name}.json`),
      JSON.stringify({ ...state, version: 1, direct: false }),
    );
    await assert.rejects(destroy(name, run), /Legacy sandbox session/);
    assert.ok(!calls.some((c) => c.args[0] === "rm"));
  }));
test("a launch that fails during creation can still be destroyed", async () =>
  fixture(async ({ project, run, calls, control }) => {
    control.createFails = true;
    await assert.rejects(launch(target, { agent: "claude", project }, run), /Session retained/);
    const name = calls.find((c) => c.args[0] === "create")!.args[2];
    await destroy(name, run);
    assert.equal((await loadState(name)).phase, "destroyed");
    assert.ok(!calls.some((c) => c.args[0] === "rm"));
  }));
test("without a project path the workspace starts empty and never touches the current directory", async () =>
  fixture(async ({ run, calls }) => {
    const name = await launch(target, { agent: "claude" }, run);
    assert.ok(!calls.some((c) => c.tool === "git" && c.args[0] === "rev-parse"));
    assert.ok(!calls.some((c) => c.args[0] === "cp"));
    assert.ok(!calls.some((c) => c.args.at(-1) === "init"));
    const create = calls.find((c) => c.args[0] === "create")!;
    assert.equal(create.args.at(-1), "claude");
    const state = await loadState(name);
    assert.equal(state.project, undefined);
    await destroy(name, run);
  }));
test("stored non-model, non-github sbx secrets stop launch before creating a sandbox", async () =>
  fixture(async ({ project, run, calls, control }) => {
    control.secrets = [{ scope: "global", type: "service", name: "ghcr" }];
    await assert.rejects(launch(target, { agent: "claude", project }, run), /"ghcr"/);
    assert.ok(!calls.some((c) => c.args[0] === "create" || c.args[1] === "assume-role"));
  }));
test("a stored github secret is tolerated, widens the allowlist, and is handed to inject", async () =>
  fixture(async ({ project, run, calls, control }) => {
    control.secrets = [{ scope: "global", type: "service", name: "github" }];
    const name = await launch(target, { agent: "claude", project }, run);
    assert.ok(calls.some((c) => c.args[1] === "allow" && c.args.at(-1) === "api.github.com:443"));
    const inject = calls.find((c) => c.args.at(-1) === "inject")!;
    assert.equal(JSON.parse(inject.options.input!).github, true);
    await destroy(name, run);
  }));
test("resume repeats host checks, renews only near expiry, and refuses failed launches", async () =>
  fixture(async ({ run, calls, control }) => {
    const name = await launch(target, { agent: "claude" }, run);
    const assumptions = () => calls.filter((c) => c.args[1] === "assume-role").length;
    const attaches = () => calls.filter((c) => c.args[0] === "run").length;
    assert.ok((await loadState(name)).expiresAt);
    // A fresh session reattaches after the host checks, without new credentials.
    const before = calls.length;
    await resume(name, run);
    assert.equal(assumptions(), 1);
    assert.equal(attaches(), 2);
    assert.ok(calls.slice(before).some((c) => c.args[0] === "secret"));
    assert.ok(calls.slice(before).some((c) => c.args[1] === "check"));
    // The sandbox already matches the allowlist, so no rules are re-added.
    assert.ok(!calls.slice(before).some((c) => c.args[1] === "allow" || c.args[1] === "deny"));
    // An expired session (or one launched before expiry was recorded) is renewed.
    const state = await loadState(name);
    await saveState({ ...state, expiresAt: undefined });
    await resume(name, run);
    assert.equal(assumptions(), 2);
    assert.ok(Date.parse((await loadState(name)).expiresAt!) > Date.now());
    const inject = calls.filter((c) => c.args.at(-1) === "inject").at(-1)!;
    assert.ok(!inject.args.join(" ").includes("EXAMPLE_SECRET"));
    // Host checks still gate a resume.
    control.secrets = [{ scope: "global", type: "service", name: "ghcr" }];
    await assert.rejects(resume(name, run), /"ghcr"/);
    assert.equal(attaches(), 3);
    control.secrets = [];
    await saveState({ ...state, phase: "failed" });
    await assert.rejects(resume(name, run), /Only ready sessions/);
  }));
test("resume checks an explicitly confirmed agent against the sandbox's own", async () =>
  fixture(async ({ run }) => {
    const name = await launch(target, { agent: "claude" }, run);
    await resume(name, run, "claude");
    await assert.rejects(resume(name, run, "codex"), /is a claude sandbox, not codex/);
  }));
test("only model secrets and the opt-in github secret are tolerated", () => {
  const service = (name: string) => ({ scope: "global", type: "service", name });
  const list = (...names: string[]) => ({ secrets: names.map(service), custom_secrets: [] });
  assert.deepEqual(unexpectedSecrets(list("anthropic", "openai")), []);
  assert.deepEqual(unexpectedSecrets(list("anthropic", "github")), []);
  assert.deepEqual(unexpectedSecrets(list("anthropic", "ghcr")), ['service secret "ghcr"']);
  assert.deepEqual(
    unexpectedSecrets({
      secrets: [{ scope: "global", type: "registry", name: "ghcr.io" }],
      custom_secrets: [],
    }),
    [],
  );
  assert.equal(unexpectedSecrets({ secrets: [], custom_secrets: [{}] }).length, 1);
  assert.throws(() => unexpectedSecrets({}), /schema/);
});
test("the github secret is detected independently of unrelated stored secrets", () => {
  const service = (name: string) => ({ scope: "global", type: "service", name });
  const list = (...names: string[]) => ({ secrets: names.map(service), custom_secrets: [] });
  assert.equal(hasGithubSecret(list("anthropic", "openai")), false);
  assert.equal(hasGithubSecret(list("anthropic", "github")), true);
  assert.equal(
    hasGithubSecret({ secrets: [{ scope: "global", type: "registry", name: "github" }] }),
    false,
  );
  assert.throws(() => hasGithubSecret({}), /schema/);
});
test("sbx version is a minimum: equal and newer pass, older names an upgrade command", () => {
  for (const version of ["0.46.0", "0.46.1", "0.47.0", "0.100.0", "1.0.0"])
    checkSbxVersion(`sbx version: v${version} abc123`, "0.46.0");
  checkSbxVersion("v0.46.0", "0.46.0");
  for (const version of ["0.45.9", "0.9.0", "0.4.60"])
    assert.throws(
      () => checkSbxVersion(`sbx version: v${version} abc123`, "0.46.0"),
      (error: Error) =>
        error.message.includes(`0.46.0 or later is required, found v${version}`) &&
        error.message.includes(sbxUpgradeHint()),
    );
  assert.throws(() => checkSbxVersion("garbage", "0.46.0"), /Could not read the sbx version/);
  assert.equal(sbxUpgradeHint("win32"), "winget upgrade Docker.sbx");
  assert.equal(sbxUpgradeHint("darwin"), "brew upgrade docker/tap/sbx");
  assert.match(sbxUpgradeHint("linux"), /docker-sbx/);
});
