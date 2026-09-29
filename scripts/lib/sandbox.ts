import { randomBytes } from "node:crypto";
import { access, mkdir, readFile, realpath, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { assumeRestrictedRole, validateLifetime } from "./aws.ts";
import type { NetworkConfig } from "./network.ts";
import { auditPolicy, blockedProbes, destinations, policyChanges, probes } from "./network.ts";
import type { Runner, RunOptions } from "./process.ts";
import { run as execute, gitEnvironment, hostEnvironment, json, successful } from "./process.ts";
import type { Target } from "./profiles.ts";
import type { State } from "./state.ts";
import { loadState, saveState, stateRoot, withTemp } from "./state.ts";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const bootstrap = "/opt/readonly-sandbox/bootstrap.ts";
// Agent-owned and outside the project: sbx cp writes root-owned files, which
// agent cannot unlink from sticky-bit /tmp.
const inputBundle = "/home/agent/readonly-input.bundle";
const outputBundle = "/tmp/readonly-output.bundle";
export interface Runtime {
  minSbxVersion: string;
  templates: Record<string, { base: string; tag: string }>;
}
export interface LaunchOptions {
  agent: string;
  project?: string;
  direct?: boolean;
}
interface Inspection {
  name: string;
  agent: string;
  runtime_mounts: unknown[];
  workspace?: string;
  workspaces?: unknown[];
  [key: string]: unknown;
}
interface Snapshot {
  fingerprint: string;
  tree: string;
  head: string;
  commit?: string;
}

// Host tools always run with a sanitized environment and withheld output.
async function tool(
  run: Runner,
  command: string,
  args: string[],
  operation: string,
  options: RunOptions = {},
): Promise<string> {
  return successful(await run(command, args, { env: hostEnvironment(), ...options }), operation);
}
const sbx = (run: Runner, args: string[], operation: string, options?: RunOptions) =>
  tool(run, "sbx", args, operation, options);
async function sbxJson<T>(run: Runner, args: string[], operation: string): Promise<T> {
  return json<T>(await run("sbx", args, { env: hostEnvironment() }), operation);
}
const git = (run: Runner, args: string[], cwd: string, operation: string) =>
  tool(run, "git", args, operation, { cwd, env: gitEnvironment() });

export async function configuration(): Promise<{ runtime: Runtime; network: NetworkConfig }> {
  const [runtime, network] = await Promise.all(
    ["runtime", "network-policy"].map((name) =>
      readFile(join(root, "config", `${name}.json`), "utf8"),
    ),
  );
  return { runtime: JSON.parse(runtime), network: JSON.parse(network) };
}
// Model authentication stays managed by sbx; any other stored service secret
// is injected into every sandbox and would give the agent unrelated access.
// Either model secret is tolerated for either agent: the sbx proxy applies it
// only on that provider's hosts, which the audited allowlist admits only for
// the matching agent.
const modelSecrets = ["anthropic", "openai"];
interface SecretList {
  secrets?: { scope?: string; type?: string; name?: string }[];
  custom_secrets?: unknown[];
}
export function unexpectedSecrets(list: SecretList): string[] {
  if (!Array.isArray(list.secrets) || !Array.isArray(list.custom_secrets))
    throw new Error("Unsupported sbx secret JSON schema.");
  const unexpected = list.secrets
    // Registry secrets stay on the host unless explicitly shared with sandboxes.
    .filter((secret) => secret.type !== "registry")
    .filter((secret) => secret.type !== "service" || !modelSecrets.includes(secret.name ?? ""))
    .map((secret) => `${secret.type ?? "unknown"} secret ${JSON.stringify(secret.name ?? "")}`);
  if (list.custom_secrets.length) unexpected.push(`${list.custom_secrets.length} custom secret(s)`);
  return unexpected;
}

// config/runtime.json records the oldest sbx version known to work. Newer
// versions are accepted optimistically; when one breaks the launcher, fix it
// and raise the minimum.
export function sbxUpgradeHint(platform: NodeJS.Platform = process.platform): string {
  if (platform === "win32") return "winget upgrade Docker.sbx";
  if (platform === "darwin") return "brew upgrade docker/tap/sbx";
  return "sudo apt install --only-upgrade docker-sbx (or the latest package from https://github.com/docker/sbx-releases/releases)";
}

const semver = (value: string) => value.split(".").map(Number);

export function checkSbxVersion(output: string, minimum: string): void {
  const found = /v(\d+\.\d+\.\d+)/.exec(output)?.[1];
  if (!found)
    throw new Error(
      `Could not read the sbx version from "sbx version"; sbx ${minimum} or later is required.`,
    );
  const [have, need] = [semver(found), semver(minimum)];
  const difference = have.map((part, i) => part - need[i]).find((delta) => delta !== 0) ?? 0;
  if (difference < 0)
    throw new Error(
      `sbx ${minimum} or later is required, found v${found}. To upgrade: ${sbxUpgradeHint()}, then restart the sbx daemon.`,
    );
}

export async function prerequisites(run: Runner, runtime: Runtime): Promise<void> {
  const aws = await tool(run, "aws", ["--version"], "AWS CLI version check");
  const version = /aws-cli\/2\.(\d+)\./.exec(aws);
  if (!version || Number(version[1]) < 32)
    throw new Error("AWS CLI v2.32 or later is required for aws login.");
  checkSbxVersion(await sbx(run, ["version"], "sbx version check"), runtime.minSbxVersion);
  await tool(run, "git", ["--version"], "Git version check");
  const mcp = await sbxJson<{ servers: unknown[] }>(
    run,
    ["mcp", "ls", "--json"],
    "MCP configuration check",
  );
  if (!Array.isArray(mcp.servers) || mcp.servers.length)
    throw new Error(
      "This initial implementation requires an sbx setup with no registered MCP servers. Use a dedicated setup; global MCP settings are never changed.",
    );
  const socket = await sbx(
    run,
    ["settings", "get", "ssh.agentSocketPath"],
    "SSH forwarding configuration check",
  );
  if (socket && socket !== '""')
    throw new Error(
      "A fixed host SSH agent socket is configured in sbx; disable it in a dedicated setup.",
    );
  const forwarding = await sbx(
    run,
    ["settings", "get", "ssh.agentForwardingEnabled"],
    "SSH forwarding safety check",
  );
  if (forwarding !== "false")
    throw new Error(
      "sbx SSH agent forwarding must be disabled in a dedicated setup (ssh.agentForwardingEnabled=false). A sanitized client environment alone does not disable its live socket.",
    );
  const secrets = unexpectedSecrets(
    await sbxJson<SecretList>(run, ["secret", "ls", "--json"], "sbx secret check"),
  );
  if (secrets.length)
    throw new Error(
      `sbx has stored secrets that it would inject into every sandbox: ${secrets.join(", ")}. Use a dedicated setup without them (for example, sbx secret rm github); secrets are never changed automatically.`,
    );
}

// Global policy when name is omitted, otherwise the sandbox's effective policy.
const listPolicy = (run: Runner, name?: string) =>
  sbxJson<unknown>(
    run,
    ["policy", "ls", ...(name ? [name] : []), "--json", "--type", "network"],
    "Network policy inspection",
  );
async function checkNetwork(run: Runner, name: string, allowed: string[]): Promise<void> {
  const expected = [
    ...probes(allowed).map((host) => [host, true] as const),
    ...blockedProbes(allowed).map((host) => [host, false] as const),
  ];
  for (const [host, allow] of expected) {
    // sbx exits 1 for a denied destination (still printing its decision), so
    // exit 0/1 must agree with the reported decision; anything else fails.
    const result = await run(
      "sbx",
      ["policy", "check", "network", "--sandbox", name, "--json", host],
      { env: hostEnvironment() },
    );
    let response: { allowed?: unknown; target?: unknown };
    try {
      response = JSON.parse(result.stdout);
    } catch {
      throw new Error(`Network authorization check failed (exit ${result.code}).`);
    }
    if (
      typeof response.allowed !== "boolean" ||
      response.target !== host ||
      result.code !== (response.allowed ? 0 : 1)
    )
      throw new Error("Unexpected sbx network authorization response.");
    if (response.allowed !== allow)
      throw new Error("Effective network policy does not match the required allowlist.");
  }
}
// Agent kits add exact download/package/MCP endpoints. Narrow only this
// sandbox; explicit scoped denies override those matching allows.
// On resume this also converges an older sandbox to the current allowlist.
// The result is audited and checked destination by destination either way.
async function applyNetworkPolicy(run: Runner, name: string, allowed: string[]): Promise<void> {
  const changes = policyChanges(await listPolicy(run, name), allowed, name);
  for (const host of changes.allow)
    await sbx(
      run,
      ["policy", "allow", "network", "--sandbox", name, host],
      "Sandbox network allow rule",
    );
  for (const resource of changes.deny)
    await sbx(
      run,
      ["policy", "deny", "network", "--sandbox", name, resource],
      "Sandbox scoped network restriction",
    );
  auditPolicy(await listPolicy(run, name), allowed, name);
  await checkNetwork(run, name, allowed);
}
async function exists(run: Runner, name: string): Promise<boolean> {
  const list = await sbxJson<{ sandboxes?: { name?: string }[] }>(
    run,
    ["ls", "--json"],
    "Sandbox listing",
  );
  if (!Array.isArray(list.sandboxes)) throw new Error("Unsupported sbx list JSON schema.");
  return list.sandboxes.some((sandbox) => sandbox.name === name);
}
function inside(
  run: Runner,
  name: string,
  command: string,
  options: { input?: string; cwd?: string } = {},
): Promise<string> {
  const { input, cwd } = options;
  return sbx(
    run,
    [
      "exec",
      ...(input ? ["-i"] : []),
      ...(cwd ? ["--workdir", cwd] : []),
      name,
      "node",
      bootstrap,
      command,
    ],
    `Sandbox ${command}`,
    { input },
  );
}
function parseSnapshot(text: string): Snapshot {
  let snapshot: Snapshot;
  try {
    snapshot = JSON.parse(text);
  } catch {
    throw new Error("Invalid sandbox snapshot response.");
  }
  if (
    !/^[a-f0-9]{64}$/.test(snapshot.fingerprint) ||
    !/^[a-f0-9]{40,64}$/.test(snapshot.head) ||
    !/^[a-f0-9]{40,64}$/.test(snapshot.tree)
  )
    throw new Error("Invalid sandbox snapshot identifiers.");
  return snapshot;
}

export async function doctor(
  target: Target,
  agent = "claude",
  run: Runner = execute,
): Promise<void> {
  const { runtime, network } = await configuration();
  await prerequisites(run, runtime);
  auditPolicy(await listPolicy(run), destinations(network, agent, target));
  const session = await assumeRestrictedRole(target, run);
  console.log(
    `Direct assumption verified: ${session.identity.Arn}\nExpires: ${session.credentials.Expiration}\nHost checks passed. Sandbox mounts, template, effective policy and in-VM identity are checked during launch.`,
  );
}

export async function launch(
  target: Target,
  options: LaunchOptions,
  run: Runner = execute,
): Promise<string> {
  const { runtime, network } = await configuration();
  const allowed = destinations(network, options.agent, target);
  await prerequisites(run, runtime);
  auditPolicy(await listPolicy(run), allowed); // Fail before creating resources or minting credentials.
  // Without --project the sandbox starts from an empty workspace. The current
  // directory is never a default: mise tasks always run from the launcher root.
  if (options.direct && options.project === undefined)
    throw new Error("--direct requires --project.");
  const project =
    options.project === undefined ? undefined : await realpath(resolve(options.project));
  if (project) {
    const home = await realpath(homedir());
    const homeFromProject = relative(project, home);
    if (!homeFromProject || (!homeFromProject.startsWith("..") && !isAbsolute(homeFromProject)))
      throw new Error("The project must not be the host home or an ancestor of it.");
  }
  const name = `ro-${options.agent}-${randomBytes(6).toString("hex")}`;
  const state: State = {
    version: 1,
    name,
    agent: options.agent,
    target,
    project,
    direct: !!options.direct,
    phase: "creating",
    createdAt: new Date().toISOString(),
  };
  if (project && !state.direct) {
    const top = await git(
      run,
      ["rev-parse", "--show-toplevel"],
      project,
      "Git repository check (--project must be a repository root; use --direct, or omit --project for an empty workspace)",
    );
    if ((await realpath(top)) !== project)
      throw new Error("Clone mode requires --project to be the repository root.");
    const dirty = await git(
      run,
      ["status", "--porcelain", "--untracked-files=all"],
      project,
      "Git worktree check",
    );
    if (dirty)
      throw new Error(
        "Clone mode transfers committed HEAD only. Commit/stash changes first, or explicitly use --direct.",
      );
    await git(run, ["rev-parse", "--verify", "HEAD"], project, "Git HEAD check");
  }
  await saveState(state);
  console.log(
    `Creating ${name}: profile=${JSON.stringify(target.profile)} source=${JSON.stringify(target.sourceProfile)} role=${target.roleArn} region=${target.region}`,
  );
  try {
    await sbx(
      run,
      [
        "create",
        "--name",
        name,
        "--skills",
        "off",
        "--static-mcp=",
        "--pull",
        "never",
        "--template",
        runtime.templates[options.agent].tag,
        options.agent,
        ...(state.direct && project ? [project] : []),
      ],
      "Sandbox creation (build the template first)",
      { timeout: 600_000 },
    );
    const info = await sbxJson<Inspection>(run, ["inspect", name, "--json"], "Sandbox inspection");
    if (
      info.name !== name ||
      info.agent !== options.agent ||
      !Array.isArray(info.runtime_mounts) ||
      info.runtime_mounts.length
    )
      throw new Error("Unexpected sandbox identity or runtime mounts.");
    // Mountless clone mode has neither workspace nor additional workspaces.
    if (
      !state.direct &&
      (info.workspace || (Array.isArray(info.workspaces) && info.workspaces.length))
    )
      throw new Error("Clone sandbox unexpectedly exposes a host workspace.");
    const checked = JSON.parse(await inside(run, name, "check")) as { cwd: string; home: string };
    if (!checked.cwd?.startsWith("/") || checked.home !== "/home/agent")
      throw new Error("Unexpected template working directory or user.");
    state.workspace = checked.cwd;
    await applyNetworkPolicy(run, name, allowed);
    await inside(run, name, "probe-network");
    if (project && !state.direct)
      await withTemp(async (dir) => {
        const bundle = join(dir, "input.bundle");
        await git(run, ["bundle", "create", bundle, "HEAD"], project, "Private clone bundle");
        await sbx(run, ["cp", bundle, `${name}:${inputBundle}`], "Private clone transfer");
        state.baseFingerprint = parseSnapshot(
          await inside(run, name, "clone", { cwd: state.workspace }),
        ).fingerprint;
      });
    else if (!project)
      state.baseFingerprint = parseSnapshot(
        await inside(run, name, "init", { cwd: state.workspace }),
      ).fingerprint;
    state.expiresAt = await handOffSession(run, name, target);
    state.phase = "ready";
    await saveState(state);
    console.log(
      `Ready: ${name}\nExpires: ${state.expiresAt}\nCollect: mise run sandbox:collect ${name}\nResume: mise run sandbox:resume ${name}`,
    );
    await attach(run, name);
    return name;
  } catch (error) {
    if (state.phase !== "ready") state.phase = "failed";
    await saveState(state);
    // Do not erase work or credentials blindly after an interrupted launch.
    // Stop only this newly created sandbox; recovery uses managed lifecycle tasks.
    await run("sbx", ["stop", name], { env: hostEnvironment() }).catch(() => {});
    throw new Error(
      `${error instanceof Error ? error.message : "Launch failed."}\nSession retained: ${name}. Use sandbox:destroy when no work needs recovery.`,
    );
  }
}

// Assume the restricted role on the host and hand the session to the sandbox,
// which verifies its identity before replacing any previous session.
async function handOffSession(run: Runner, name: string, target: Target): Promise<string> {
  const session = await assumeRestrictedRole(target, run);
  validateLifetime(session.credentials.Expiration);
  // Secrets travel on stdin, never as arguments or through a host file.
  await inside(run, name, "inject", {
    input: JSON.stringify({
      credentials: session.credentials,
      identity: session.identity,
      region: target.region,
    }),
  });
  return session.credentials.Expiration;
}

async function attach(run: Runner, name: string): Promise<void> {
  const agent = await run("sbx", ["run", "--name", name], {
    env: hostEnvironment(),
    interactive: true,
    timeout: 24 * 60 * 60 * 1000,
  });
  if (agent.code !== 0)
    throw new Error(
      `Agent session exited with status ${agent.code}; sandbox work is preserved as ${name}.`,
    );
}

// Sessions this close to expiry are renewed before reattaching.
const renewalWindow = 15 * 60_000;

export async function resume(name: string, run: Runner = execute): Promise<void> {
  const state = await loadState(name);
  if (state.phase !== "ready")
    throw new Error(
      `Only ready sessions can be resumed (this one is ${state.phase}). Use sandbox:destroy for failed launches.`,
    );
  // Host policy, secrets and settings may have changed since launch; repeat
  // every host-side check that guards a credential handoff.
  const { runtime, network } = await configuration();
  const allowed = destinations(network, state.agent, state.target);
  await prerequisites(run, runtime);
  auditPolicy(await listPolicy(run), allowed);
  if (!(await exists(run, name)))
    throw new Error(
      "Sandbox not found in this sbx setup; check that you are using the setup it was launched from.",
    );
  await applyNetworkPolicy(run, name, allowed);
  const remaining = Date.parse(state.expiresAt ?? "") - Date.now();
  if (!(remaining > renewalWindow)) {
    console.log(`Renewing the restricted AWS session for ${name}.`);
    state.expiresAt = await handOffSession(run, name, state.target);
    await saveState(state);
  }
  console.log(`Resuming ${name}\nExpires: ${state.expiresAt}`);
  await attach(run, name);
}

export async function collect(name: string, run: Runner = execute): Promise<string> {
  const state = await loadState(name);
  if (state.phase === "destroyed") throw new Error("Sandbox was already destroyed.");
  if (state.direct)
    throw new Error("Direct-mode work is already in the host checkout; use Git there.");
  if (!state.workspace) throw new Error("Sandbox workspace was not initialized.");
  await sbx(run, ["stop", name], "Stop agent before collection");
  const snapshot = parseSnapshot(await inside(run, name, "collect", { cwd: state.workspace }));
  const dir = join(
    stateRoot(),
    "collections",
    name,
    `${Date.now()}-${randomBytes(3).toString("hex")}`,
  );
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const bundle = join(dir, "work.bundle");
  await sbx(run, ["cp", `${name}:${outputBundle}`, bundle], "Work collection");
  // Bundles carry full history, so an empty repository can verify them.
  await withTemp(async (repo) => {
    await git(run, ["init", "--bare", "--quiet", "."], repo, "Verification repository");
    await git(run, ["bundle", "verify", bundle], repo, "Collected bundle verification");
  });
  await writeFile(join(dir, "snapshot.json"), `${JSON.stringify(snapshot, null, 2)}\n`);
  state.collectedFingerprint = snapshot.fingerprint;
  state.collectedBundle = bundle;
  await saveState(state);
  const fetch = (repo: string) =>
    `git -C "${repo}" fetch "${bundle}" refs/readonly-export/snapshot`;
  const review = state.project
    ? `${fetch(state.project)}\n  git -C "${state.project}" diff HEAD FETCH_HEAD`
    : `git init "${join(dir, "review")}"\n  ${fetch(join(dir, "review"))}\n  git -C "${join(dir, "review")}" checkout FETCH_HEAD`;
  console.log(`Collected: ${bundle}\nReview with:\n  ${review}`);
  return bundle;
}

export async function destroy(name: string, force: boolean, run: Runner = execute): Promise<void> {
  const state = await loadState(name);
  if (state.phase === "destroyed") throw new Error("Sandbox was already destroyed.");
  if (!(await exists(run, name))) {
    // A launch that failed before or during creation has no sandbox to stop.
    // A ready session that is missing may live in a different sbx setup.
    if (state.phase === "ready")
      throw new Error(
        "Sandbox not found in this sbx setup; check that you are using the setup it was launched from.",
      );
    state.phase = "destroyed";
    await saveState(state);
    console.log(`${name} was never created or is already gone; metadata marked destroyed.`);
    return;
  }
  await sbx(run, ["stop", name], "Stop agent before destruction check");
  if (!state.direct && !force) {
    if (!state.workspace || !state.baseFingerprint)
      throw new Error(
        "Cannot establish whether this incomplete sandbox contains work; inspect it and use --force to discard it.",
      );
    const current = parseSnapshot(await inside(run, name, "snapshot", { cwd: state.workspace }));
    if (current.fingerprint !== state.baseFingerprint) {
      if (current.fingerprint !== state.collectedFingerprint || !state.collectedBundle)
        throw new Error(
          "Sandbox contains uncollected work. Collect it first, or use --force to discard it.",
        );
      await access(state.collectedBundle).catch(() => {
        throw new Error("Previously collected bundle is missing; collect again before destroying.");
      });
    }
  }
  await sbx(run, ["rm", "--force", name], "Managed sandbox removal");
  state.phase = "destroyed";
  await saveState(state);
  console.log(`Destroyed ${name}. Collected bundles are retained.`);
}

export async function buildTemplate(agent: string, run: Runner = execute): Promise<void> {
  const { runtime } = await configuration();
  const template = runtime.templates[agent];
  if (!template) throw new Error("Template agent must be claude or codex.");
  console.log(`Building ${template.tag}; pinned image downloads can take several minutes.`);
  await withTemp(async (dir) => {
    await tool(
      run,
      "docker",
      [
        "build",
        "--build-arg",
        `BASE_IMAGE=${template.base}`,
        "--tag",
        template.tag,
        "--file",
        join(root, "sandbox", "Dockerfile"),
        root,
      ],
      "Template build",
      { interactive: true, timeout: 1_800_000 },
    );
    const archive = join(dir, "template.tar");
    await tool(
      run,
      "docker",
      ["image", "save", "--output", archive, template.tag],
      "Template export",
      { timeout: 600_000 },
    );
    await sbx(run, ["template", "load", archive], "Sandbox template load", { timeout: 600_000 });
  });
  console.log(`Loaded ${template.tag}.`);
}
