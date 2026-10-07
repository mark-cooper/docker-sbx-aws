import assert from "node:assert/strict";
import { mkdtemp, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { configuration } from "../scripts/lib/config.ts";
import { metadataHosts } from "../scripts/lib/network.ts";
import type { Runner, RunOptions } from "../scripts/lib/process.ts";
import type { Target } from "../scripts/lib/profiles.ts";
import {
  checkSbxVersion,
  destroy,
  launch,
  resume,
  sbxUpgradeHint,
  unexpectedSecrets,
} from "../scripts/lib/sandbox.ts";
import { defaultName, loadState, saveState } from "../scripts/lib/state.ts";

const { runtime, network } = await configuration();
const { minSbxVersion, renewWithinSeconds } = runtime;
const denies = [...metadataHosts, ...(network.blockedHosts ?? [])];

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
      toolsFail: boolean;
      createFails: boolean;
      forwarding: boolean;
      mcpServers: number;
      allowExample: boolean;
      dropDenies: boolean;
      ignoreDenies: boolean;
      otherSandboxes: string[];
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
      toolsFail: false,
      createFails: false,
      forwarding: false,
      mcpServers: 0,
      allowExample: false,
      // Stands in for an sbx that does not record the deny rules it is given.
      dropDenies: false,
      // Stands in for an sbx that records deny rules but does not enforce them.
      ignoreDenies: false,
      otherSandboxes: [] as string[],
      secrets: [] as { scope: string; type: string; name: string }[],
    };
  let name = "",
    agent = "",
    mounted = false,
    identity = {};
  // Sandbox-scoped rules the launcher has added, as sbx would record them.
  const sandboxAllows = new Set<string>();
  const sandboxDenies = new Set<string>();
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
    else if (args[0] === "mcp")
      result = {
        servers: Array.from({ length: control.mcpServers }, (_, i) => ({ name: `m${i}` })),
      };
    else if (args[0] === "secret") result = { secrets: control.secrets, custom_secrets: [] };
    else if (args[0] === "settings")
      result = args[2] === "ssh.agentForwardingEnabled" ? String(control.forwarding) : "";
    else if (args[0] === "create") {
      if (control.createFails) code = 1;
      else {
        name = args[args.indexOf("--name") + 1];
        mounted = args.includes(project);
        agent = args.at(mounted ? -2 : -1)!;
      }
    } else if (args[0] === "rm") name = "";
    else if (args[0] === "ls")
      result = {
        sandboxes: [...(name ? [name] : []), ...control.otherSandboxes].map((n) => ({
          name: n,
          status: "stopped",
        })),
      };
    else if (args[0] === "inspect")
      result = {
        name,
        agent,
        runtime_mounts: [],
        workspace: mounted ? "/home/agent/workspace" : undefined,
      };
    else if (args[0] === "policy" && args[1] === "allow")
      for (const resource of args.at(-1)!.split(",")) sandboxAllows.add(resource);
    else if (args[0] === "policy" && args[1] === "deny") {
      if (!control.dropDenies)
        for (const resource of args.at(-1)!.split(",")) sandboxDenies.add(resource);
    } else if (args[0] === "policy" && args[1] === "ls")
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
            ? [
                ...[...sandboxAllows].map((resource) => ["allow", resource]),
                ...[...sandboxDenies].map((resource) => ["deny", resource]),
              ].map(([decision, resource]) => ({
                resource_type: "network",
                status: "active",
                decision,
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
      // allowExample stands in for a developer's broader default policy.
      // A deny without a port covers every port and wins over any allow,
      // including the developer's own (pypi.org stands in for those).
      const host = probe.replace(/:\d+$/, "").replace(/^\[(.*)\]$/, "$1");
      const denied =
        !control.ignoreDenies &&
        [...sandboxDenies].some(
          (rule) =>
            rule === host ||
            rule === `${host}/128` ||
            (rule.startsWith("**.") &&
              (host === rule.slice(3) || host.endsWith(`.${rule.slice(3)}`))),
        );
      const allowed =
        !denied &&
        ((control.allowExample && probe === "example.com:443") ||
          probe === "pypi.org:443" ||
          [...sandboxAllows].some(
            (rule) =>
              rule === probe ||
              (rule.startsWith("**.") &&
                (probe === rule.slice(3) || probe.endsWith(`.${rule.slice(3)}`))),
          ));
      result = { allowed, target: args.at(-1) };
      if (!allowed) code = 1;
    } else if (args[0] === "exec") {
      const command = args.at(-1);
      if (command === "check") result = { cwd: "/home/agent/workspace", home: "/home/agent" };
      else if (command === "inject") {
        result = { identity };
        if (control.injectFails) code = 1;
      } else if (command === "tools") {
        result = "installed";
        if (control.toolsFail) code = 1;
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
    // The role is assumed while the sandbox is prepared, but its credentials
    // reach the sandbox only after every sandbox check.
    assert.ok(
      calls.findIndex((c) => c.args[1] === "assume-role") <
        calls.findIndex((c) => c.args.at(-1) === "probe-network"),
    );
    assert.ok(
      calls.findIndex((c) => c.args.at(-1) === "probe-network") <
        calls.findIndex((c) => c.args.at(-1) === "inject"),
    );
    // The project's mise tools are installed after the network checks, before
    // the handoff, by the template's Node rather than a project shim.
    const tools = calls.findIndex((c) => c.args.at(-1) === "tools");
    assert.ok(calls.findIndex((c) => c.args.at(-1) === "probe-network") < tools);
    assert.ok(tools < calls.findIndex((c) => c.args.at(-1) === "inject"));
    for (const call of calls.filter((c) => c.args[0] === "exec"))
      assert.equal(call.args.at(-3), "/usr/local/bin/node");
    // The allowlist is added in one call, and so are metadata and the blocks.
    assert.equal(calls.filter((c) => c.args[1] === "allow").length, 1);
    const denyCalls = calls.filter((c) => c.args[0] === "policy" && c.args[1] === "deny");
    assert.equal(denyCalls.length, 1);
    assert.deepEqual(denyCalls[0].args.slice(3), ["--sandbox", name, denies.join(",")]);
    // A block is checked against the developer's own allow of it.
    assert.ok(calls.some((c) => c.args[1] === "check" && c.args.at(-1) === "pypi.org:443"));
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
test("a launch stops before handoff when denies are not recorded or not enforced", async () => {
  for (const [failure, message] of [
    ["dropDenies", /Deny rules are missing/],
    ["ignoreDenies", /block lists/],
  ] as const)
    await fixture(async ({ run, calls, control }) => {
      control[failure] = true;
      await assert.rejects(launch(target, { agent: "claude" }, run), message);
      assert.ok(!calls.some((c) => c.args.at(-1) === "inject" || c.args[0] === "run"));
    });
});
test("allow-all host policy stops before creating a sandbox or contacting AWS STS", async () =>
  fixture(async ({ project, run, calls, control }) => {
    control.broadPolicy = true;
    await assert.rejects(launch(target, { agent: "claude", project }, run), /every destination/);
    assert.ok(!calls.some((c) => c.args[0] === "create" || c.args[0] === "sts"));
  }));
test("the host setup is tolerated, extra grants are reported, and only the configured blocks are denied", async () =>
  fixture(async ({ run, calls, control }) => {
    control.secrets = [{ scope: "global", type: "service", name: "github" }];
    control.forwarding = true;
    control.mcpServers = 1;
    control.allowExample = true;
    const warnings: string[] = [];
    const warn = console.warn;
    console.warn = (message: string) => warnings.push(message);
    try {
      await launch(target, { agent: "claude" }, run);
    } finally {
      console.warn = warn;
    }
    const grants = warnings.find((w) => w.includes("besides the restricted AWS session"))!;
    for (const grant of ["SSH agent forwarding", '"github"', "MCP server"])
      assert.ok(grants.includes(grant), grant);
    const denied = calls
      .filter((c) => c.args[0] === "policy" && c.args[1] === "deny")
      .flatMap((c) => c.args.at(-1)!.split(","));
    assert.deepEqual(denied, denies);
    // Metadata is still checked; example.com is allowed, so no in-VM denial probe.
    assert.ok(calls.some((c) => c.args[1] === "check" && c.args.at(-1) === "169.254.169.254:80"));
    assert.ok(!calls.some((c) => c.args.at(-1) === "probe-network"));
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
test("a failed mise install warns but still hands off and attaches, on launch and resume", async () =>
  fixture(async ({ project, run, calls, control }) => {
    control.toolsFail = true;
    const warnings: string[] = [];
    const warn = console.warn;
    console.warn = (message: string) => warnings.push(message);
    try {
      const name = await launch(target, { agent: "claude", project }, run);
      await resume(name, run);
    } finally {
      console.warn = warn;
    }
    assert.equal(calls.filter((c) => c.args.at(-1) === "tools").length, 2);
    assert.equal(warnings.filter((w) => w.includes("mise install failed")).length, 2);
    assert.ok(calls.some((c) => c.args.at(-1) === "inject"));
    assert.equal(calls.filter((c) => c.args[0] === "run").length, 2);
  }));
test("a sandbox failure is reported over a concurrent role assumption failure", async () =>
  fixture(async ({ project, run, calls, control }) => {
    control.createFails = true;
    control.denyAws = true;
    await assert.rejects(launch(target, { agent: "claude", project }, run), /Sandbox creation/);
    assert.ok(!calls.some((c) => c.args.at(-1) === "inject"));
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
    assert.ok(!calls.some((c) => c.args.at(-1) === "tools"));
    const create = calls.find((c) => c.args[0] === "create")!;
    assert.equal(create.args.at(-1), "claude");
    const state = await loadState(name);
    assert.equal(state.project, undefined);
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
    // The configured renewal window decides whether a live session is renewed.
    const state = await loadState(name);
    const expiresIn = (seconds: number) => new Date(Date.now() + seconds * 1000).toISOString();
    await saveState({ ...state, expiresAt: expiresIn(renewWithinSeconds + 60) });
    await resume(name, run);
    assert.equal(assumptions(), 1);
    await saveState({ ...state, expiresAt: expiresIn(renewWithinSeconds - 60) });
    await resume(name, run);
    assert.equal(assumptions(), 2);
    // An expired session (or one launched before expiry was recorded) is renewed.
    await saveState({ ...state, expiresAt: undefined });
    await resume(name, run);
    assert.equal(assumptions(), 3);
    assert.ok(Date.parse((await loadState(name)).expiresAt!) > Date.now());
    const inject = calls.filter((c) => c.args.at(-1) === "inject").at(-1)!;
    assert.ok(!inject.args.join(" ").includes("EXAMPLE_SECRET"));
    // Host checks still gate a resume.
    control.broadPolicy = true;
    await assert.rejects(resume(name, run), /every destination/);
    assert.equal(attaches(), 5);
    control.broadPolicy = false;
    await saveState({ ...state, phase: "failed" });
    await assert.rejects(resume(name, run), /Only ready sessions/);
  }));
test("without a target the sandbox gets no AWS session, AWS domains or AWS CLI check", async () =>
  fixture(async ({ run, calls }) => {
    const name = await launch(undefined, { agent: "claude" }, run);
    assert.ok(!calls.some((c) => c.tool === "aws"));
    assert.ok(!calls.some((c) => c.args.includes("inject")));
    const allows = calls
      .filter((c) => c.args[1] === "allow")
      .flatMap((c) => c.args.at(-1)!.split(","));
    assert.ok(allows.includes("api.anthropic.com:443"));
    assert.ok(!allows.some((host) => host?.includes("amazonaws")));
    const state = await loadState(name);
    assert.equal(state.target, undefined);
    assert.equal(state.expiresAt, undefined);
    // Resume never tries to renew a session that was never issued.
    await resume(name, run);
    assert.ok(!calls.some((c) => c.tool === "aws"));
  }));
test("resume checks an explicitly confirmed agent against the sandbox's own", async () =>
  fixture(async ({ run }) => {
    const name = await launch(target, { agent: "claude" }, run);
    await resume(name, run, "claude");
    await assert.rejects(resume(name, run, "codex"), /is a claude sandbox, not codex/);
  }));
test("names default to <agent>-<directory> and --name overrides them", async () =>
  fixture(async ({ project, run, calls }) => {
    const name = await launch(target, { agent: "claude", project }, run);
    assert.equal(name, defaultName("claude", project));
    assert.match(name, /^claude-readonly-lifecycle-[a-z0-9]+$/);
    const chosen = await launch(undefined, { agent: "codex", name: "my-box" }, run);
    assert.equal(chosen, "my-box");
    assert.equal(calls.filter((c) => c.args[0] === "create").at(-1)!.args[2], "my-box");
    await assert.rejects(launch(undefined, { agent: "codex", name: "../x" }, run), /lowercase/);
  }));
test("default names are slugged sandbox names", () => {
  assert.equal(defaultName("claude", "/home/me/My_Project.v2"), "claude-my-project-v2");
  assert.equal(defaultName("codex", "/"), "codex");
  assert.equal(defaultName("codex", "/--x--"), "codex-x");
  const long = defaultName("claude", `/${"a".repeat(100)}-`);
  assert.equal(long.length, 63);
});
test("launching an existing managed sandbox reattaches only when nothing would change", async () =>
  fixture(async ({ project, run, calls }) => {
    const name = await launch(target, { agent: "claude", project }, run);
    const creates = () => calls.filter((c) => c.args[0] === "create").length;
    const attaches = () => calls.filter((c) => c.args[0] === "run").length;
    assert.equal(await launch(target, { agent: "claude", project }, run), name);
    assert.equal(creates(), 1);
    assert.equal(attaches(), 2);
    await assert.rejects(launch(target, { agent: "codex", project, name }, run), /different agent/);
    await assert.rejects(launch(target, { agent: "claude", name }, run), /different workspace/);
    await assert.rejects(launch(undefined, { agent: "claude", project }, run), /different AWS/);
    await assert.rejects(
      launch({ ...target, region: "eu-west-1" }, { agent: "claude", project }, run),
      /different AWS/,
    );
    assert.equal(creates(), 1);
    // Once destroyed, the name is free again.
    await destroy(name, run);
    await launch(undefined, { agent: "claude", project }, run);
    assert.equal(creates(), 2);
  }));
test("a sandbox name taken by an unmanaged sandbox is refused before creation", async () =>
  fixture(async ({ run, calls, control }) => {
    control.otherSandboxes = ["theirs"];
    await assert.rejects(
      launch(target, { agent: "claude", name: "theirs" }, run),
      /not managed by this launcher/,
    );
    assert.ok(!calls.some((c) => c.args[0] === "create" || c.args[1] === "assume-role"));
  }));
test("only non-model secrets are reported", () => {
  const service = (name: string) => ({ scope: "global", type: "service", name });
  const list = (...names: string[]) => ({ secrets: names.map(service), custom_secrets: [] });
  const expected = ["anthropic", "openai"];
  assert.deepEqual(unexpectedSecrets(list("anthropic", "openai"), expected), []);
  assert.deepEqual(unexpectedSecrets(list("anthropic", "github"), expected), [
    'service secret "github"',
  ]);
  assert.deepEqual(
    unexpectedSecrets(
      {
        secrets: [{ scope: "global", type: "registry", name: "ghcr.io" }],
        custom_secrets: [],
      },
      expected,
    ),
    [],
  );
  assert.equal(unexpectedSecrets({ secrets: [], custom_secrets: [{}] }, expected).length, 1);
  assert.throws(() => unexpectedSecrets({}, expected), /schema/);
  assert.deepEqual(unexpectedSecrets(list("openai"), ["anthropic"]), ['service secret "openai"']);
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
