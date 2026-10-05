import { readFile, realpath } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { assumeRestrictedRole, validateLifetime } from "./aws.ts";
import type { NetworkConfig } from "./network.ts";
import { auditPolicy, blockedProbes, destinations, missingAllows, probes } from "./network.ts";
import type { Runner, RunOptions } from "./process.ts";
import { run as execute, hostEnvironment, json, successful } from "./process.ts";
import type { Target } from "./profiles.ts";
import type { State } from "./state.ts";
import {
  defaultName,
  loadState,
  managedState,
  saveState,
  validateName,
  withTemp,
} from "./state.ts";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const bootstrap = "/opt/readonly-sandbox/bootstrap.ts";
export interface Runtime {
  minSbxVersion: string;
  // Restricted role assumed when --role is not given.
  defaultRole: string;
  templates: Record<string, { tag: string }>;
}
export interface LaunchOptions {
  agent: string;
  project?: string;
  // Defaults to <agent>-<project directory name>, or the current directory's name.
  name?: string;
}
interface Inspection {
  name: string;
  agent: string;
  runtime_mounts: unknown[];
  workspace?: string;
  workspaces?: unknown[];
  [key: string]: unknown;
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

export async function configuration(): Promise<{ runtime: Runtime; network: NetworkConfig }> {
  const [runtime, network] = await Promise.all(
    ["runtime", "network-policy"].map((name) =>
      readFile(join(root, "config", `${name}.json`), "utf8"),
    ),
  );
  return { runtime: JSON.parse(runtime), network: JSON.parse(network) };
}
// Model authentication stays managed by sbx; any other stored service secret
// is injected into every sandbox and gives the agent access beyond the AWS
// session, so it is reported at launch. Either model secret is expected for
// either agent: the sbx proxy applies it only on that provider's hosts.
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

// Host checks before any credential handoff. The developer's sbx setup is
// left alone; features that hand the agent access beyond the AWS session are
// returned so they can be reported.
export async function prerequisites(run: Runner, runtime: Runtime, aws = true): Promise<string[]> {
  if (aws) {
    const output = await tool(run, "aws", ["--version"], "AWS CLI version check");
    const version = /aws-cli\/2\.(\d+)\./.exec(output);
    if (!version || Number(version[1]) < 32)
      throw new Error("AWS CLI v2.32 or later is required for aws login.");
  }
  checkSbxVersion(await sbx(run, ["version"], "sbx version check"), runtime.minSbxVersion);
  const grants: string[] = [];
  const mcp = await sbxJson<{ servers: unknown[] }>(
    run,
    ["mcp", "ls", "--json"],
    "MCP configuration check",
  );
  if (!Array.isArray(mcp.servers)) throw new Error("Unsupported sbx MCP JSON schema.");
  if (mcp.servers.length) grants.push(`${mcp.servers.length} registered sbx MCP server(s)`);
  const socket = await sbx(
    run,
    ["settings", "get", "ssh.agentSocketPath"],
    "SSH forwarding configuration check",
  );
  const forwarding = await sbx(
    run,
    ["settings", "get", "ssh.agentForwardingEnabled"],
    "SSH forwarding safety check",
  );
  if (socket && socket !== '""') grants.push(`SSH agent forwarding from ${socket}`);
  else if (forwarding !== "false")
    grants.push("SSH agent forwarding (every key in your host agent)");
  const secrets = unexpectedSecrets(
    await sbxJson<SecretList>(run, ["secret", "ls", "--json"], "sbx secret check"),
  );
  if (secrets.length) grants.push(`stored sbx ${secrets.join(", ")}`);
  return grants;
}
function reportGrants(grants: string[]): void {
  if (grants.length)
    console.warn(
      `Warning: besides the restricted AWS session, the agent can use: ${grants.join("; ")}.`,
    );
}

// Global policy when name is omitted, otherwise the sandbox's effective policy.
const listPolicy = (run: Runner, name?: string) =>
  sbxJson<unknown>(
    run,
    ["policy", "ls", ...(name ? [name] : []), "--json", "--type", "network"],
    "Network policy inspection",
  );
// Whether sbx would admit a destination for this sandbox.
async function admitted(run: Runner, name: string, host: string): Promise<boolean> {
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
  return response.allowed;
}
async function checkNetwork(run: Runner, name: string, allowed: string[]): Promise<void> {
  const expected = [
    ...probes(allowed).map((host) => [host, true] as const),
    ...blockedProbes.map((host) => [host, false] as const),
  ];
  for (const [host, allow] of expected)
    if ((await admitted(run, name, host)) !== allow)
      throw new Error("Effective network policy does not match the required allowlist.");
}
// The in-VM probe needs a real proxy denial of example.com, so it runs only
// when the developer's policy blocks it.
async function probeInside(run: Runner, name: string): Promise<void> {
  if (await admitted(run, name, "example.com:443")) return;
  await inside(run, name, "probe-network");
}
// Add this project's allows for this sandbox only, on top of the developer's
// policy. On resume this also adds hosts since added to the allowlist. The
// result is audited and checked destination by destination either way.
async function applyNetworkPolicy(run: Runner, name: string, allowed: string[]): Promise<void> {
  for (const host of missingAllows(await listPolicy(run, name), allowed, name))
    await sbx(
      run,
      ["policy", "allow", "network", "--sandbox", name, host],
      "Sandbox network allow rule",
    );
  auditPolicy(await listPolicy(run, name), name);
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

// Without a target only the host sbx checks run.
export async function doctor(target: Target | undefined, run: Runner = execute): Promise<void> {
  const { runtime } = await configuration();
  reportGrants(await prerequisites(run, runtime, !!target));
  auditPolicy(await listPolicy(run));
  if (!target) {
    console.log("Host checks passed (no AWS profile given; role assumption not checked).");
    return;
  }
  const session = await assumeRestrictedRole(target, run);
  console.log(
    `Direct assumption verified: ${session.identity.Arn}\nExpires: ${session.credentials.Expiration}\nHost checks passed. Sandbox mounts, template, effective policy and in-VM identity are checked during launch.`,
  );
}

// Without a target the sandbox gets no AWS session and no AWS domains.
export async function launch(
  target: Target | undefined,
  options: LaunchOptions,
  run: Runner = execute,
): Promise<string> {
  // Without a project path the sandbox starts from an empty workspace; the
  // current directory is never used implicitly (only for the default name).
  const project =
    options.project === undefined ? undefined : await realpath(resolve(options.project));
  if (project) {
    const home = await realpath(homedir());
    const homeFromProject = relative(project, home);
    if (!homeFromProject || (!homeFromProject.startsWith("..") && !isAbsolute(homeFromProject)))
      throw new Error("The project must not be the host home or an ancestor of it.");
  }
  const name = options.name ?? defaultName(options.agent, project ?? process.cwd());
  validateName(name);
  // Launching an existing managed sandbox again reattaches to it, as sbx run
  // does, but only when nothing about it would change.
  const existing = await managedState(name);
  if (existing) {
    const mismatch = launchMismatch(existing, options.agent, project, target);
    if (mismatch)
      throw new Error(
        `${name} already exists with a different ${mismatch}. Reattach with mise run sbx run --name ${name}, choose another --name, or remove it first.`,
      );
    await resume(name, run);
    return name;
  }
  const { runtime, network } = await configuration();
  const allowed = destinations(network, options.agent, target);
  const grants = await prerequisites(run, runtime, !!target);
  auditPolicy(await listPolicy(run)); // Fail before creating resources or minting credentials.
  if (await exists(run, name))
    throw new Error(
      `A sandbox named ${name} already exists but is not managed by this launcher; choose another --name.`,
    );
  const state: State = {
    version: 2,
    name,
    agent: options.agent,
    target,
    project,
    phase: "creating",
    createdAt: new Date().toISOString(),
  };
  await saveState(state);
  if (!project)
    console.warn(
      "Warning: Empty workspace files stay in the sandbox and are lost when it is destroyed.",
    );
  console.log(
    target
      ? `Creating ${name}: profile=${JSON.stringify(target.profile)} source=${JSON.stringify(target.sourceProfile)} role=${target.roleArn} region=${target.region}`
      : `Creating ${name}: no AWS session`,
  );
  reportGrants(grants);
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
        ...(project ? [project] : []),
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
    // Empty mode must not expose a host workspace.
    if (!project && (info.workspace || (Array.isArray(info.workspaces) && info.workspaces.length)))
      throw new Error("Empty sandbox unexpectedly exposes a host workspace.");
    if (project && !info.workspace)
      throw new Error("Project sandbox did not mount the selected directory.");
    const checked = JSON.parse(await inside(run, name, "check")) as { cwd: string; home: string };
    if (!checked.cwd?.startsWith("/") || checked.home !== "/home/agent")
      throw new Error("Unexpected template working directory or user.");
    await applyNetworkPolicy(run, name, allowed);
    await probeInside(run, name);
    if (target) state.expiresAt = await handOffSession(run, name, target);
    state.phase = "ready";
    await saveState(state);
    console.log(
      `Ready: ${name}\n${state.expiresAt ? `Expires: ${state.expiresAt}` : "No AWS session"}\nReattach: mise run sbx run --name ${name}`,
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
      `${error instanceof Error ? error.message : "Launch failed."}\nSession retained: ${name}. Use mise run sbx rm ${name} when no work needs recovery.`,
    );
  }
}

function launchMismatch(
  state: State,
  agent: string,
  project: string | undefined,
  target: Target | undefined,
): string | undefined {
  if (state.agent !== agent) return "agent";
  if (state.project !== project) return "workspace";
  const role = (t?: Target) => t && [t.profile, t.sourceProfile, t.roleArn, t.region].join("\n");
  if (role(state.target) !== role(target)) return "AWS profile, role or region";
  return undefined;
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

export async function resume(
  name: string,
  run: Runner = execute,
  expectedAgent?: string,
): Promise<void> {
  const state = await loadState(name);
  if (expectedAgent && expectedAgent !== state.agent)
    throw new Error(`${name} is a ${state.agent} sandbox, not ${expectedAgent}.`);
  if (state.phase !== "ready")
    throw new Error(
      `Only ready sessions can be resumed (this one is ${state.phase}). Use mise run sbx rm for failed launches.`,
    );
  // Host policy, secrets and settings may have changed since launch; repeat
  // every host-side check that guards a credential handoff.
  const { runtime, network } = await configuration();
  const allowed = destinations(network, state.agent, state.target);
  reportGrants(await prerequisites(run, runtime, !!state.target));
  auditPolicy(await listPolicy(run));
  if (!(await exists(run, name)))
    throw new Error(
      "Sandbox not found in this sbx setup; check that you are using the setup it was launched from.",
    );
  await applyNetworkPolicy(run, name, allowed);
  const remaining = Date.parse(state.expiresAt ?? "") - Date.now();
  if (state.target && !(remaining > renewalWindow)) {
    console.log(`Renewing the restricted AWS session for ${name}.`);
    state.expiresAt = await handOffSession(run, name, state.target);
    await saveState(state);
  }
  console.log(
    `Resuming ${name}\n${state.expiresAt ? `Expires: ${state.expiresAt}` : "No AWS session"}`,
  );
  await attach(run, name);
}

export async function destroy(name: string, run: Runner = execute): Promise<void> {
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
  await sbx(run, ["stop", name], "Stop agent before destruction");
  await sbx(run, ["rm", "--force", name], "Managed sandbox removal");
  state.phase = "destroyed";
  await saveState(state);
  console.log(`Destroyed ${name}.`);
}

export async function buildTemplate(agent: string, run: Runner = execute): Promise<void> {
  const { runtime } = await configuration();
  const template = runtime.templates[agent];
  if (!template) throw new Error("No template is configured for that agent.");
  console.log(`Building ${template.tag}; pinned image downloads can take several minutes.`);
  await withTemp(async (dir) => {
    await tool(
      run,
      "docker",
      [
        "build",
        "--tag",
        template.tag,
        "--file",
        join(root, "sandbox", `Dockerfile.${agent}`),
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
