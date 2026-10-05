import {
  access,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import { basename, isAbsolute, join, relative, resolve } from "node:path";
import type { Target } from "./profiles.ts";

export interface State {
  version: 2;
  name: string;
  agent: string;
  // Absent for a sandbox launched without an AWS session.
  target?: Target;
  // Absent for an empty workspace.
  project?: string;
  // Expiry of the restricted AWS session last handed to the sandbox.
  expiresAt?: string;
  phase: "creating" | "ready" | "failed" | "destroyed";
  createdAt: string;
}
export const agents = ["claude", "codex"];
export function stateRoot(): string {
  return resolve(
    process.env.READONLY_SANDBOX_STATE_DIR ?? join(homedir(), ".readonly-agent-sandbox"),
  );
}
// Names become state file names and the sandbox hostname, so they are kept to
// a lowercase DNS label. Whether a sandbox is managed is decided by its state
// file, never by its name.
const namePattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
export function validName(name: string): boolean {
  return namePattern.test(name);
}
export function validateName(name: string): void {
  if (!validName(name))
    throw new Error(
      "Sandbox names use lowercase letters, digits and inner hyphens (at most 63 characters).",
    );
}
// <agent>-<directory name>, as sbx names its own sandboxes.
export function defaultName(agent: string, directory: string): string {
  const slug = basename(directory)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .slice(0, 62 - agent.length)
    .replace(/^-+|-+$/g, "");
  return slug ? `${agent}-${slug}` : agent;
}
export async function saveState(state: State): Promise<void> {
  validateName(state.name);
  await mkdir(join(stateRoot(), "sessions"), { recursive: true, mode: 0o700 });
  const path = join(stateRoot(), "sessions", `${state.name}.json`);
  const temp = `${path}.${process.pid}.tmp`;
  await writeFile(temp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  await rename(temp, path);
}
export async function loadState(name: string): Promise<State> {
  validateName(name);
  let state: State;
  let version: number;
  try {
    const parsed = JSON.parse(
      await readFile(join(stateRoot(), "sessions", `${name}.json`), "utf8"),
    );
    version = parsed.version;
    state = parsed;
  } catch {
    throw new Error("Managed session metadata not found or invalid.");
  }
  if (version === 1)
    throw new Error("Legacy sandbox session: use the previous launcher to collect or destroy it.");
  if (state.name !== name || state.version !== 2 || !agents.includes(state.agent))
    throw new Error("Invalid managed session metadata.");
  return state;
}
// The state of a sandbox this launcher manages, or undefined when the name has
// no metadata or was destroyed (and so may be reused).
export async function managedState(name: string): Promise<State | undefined> {
  if (!validName(name)) return undefined;
  try {
    await access(join(stateRoot(), "sessions", `${name}.json`));
  } catch {
    return undefined;
  }
  const state = await loadState(name);
  return state.phase === "destroyed" ? undefined : state;
}
export async function withTemp<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const parent = join(stateRoot(), "tmp");
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const dir = await mkdtemp(join(parent, "job-"));
  // Only delete the exact directory allocated by this function. Resolve its
  // parent and check containment (including on Windows) before any work, so
  // cleanup never needs to throw and mask an error from fn.
  const actualParent = await realpath(parent),
    actual = await realpath(dir);
  const inside = relative(actualParent, actual);
  if (!inside || inside.startsWith("..") || isAbsolute(inside))
    throw new Error("Refusing to use a temporary directory outside the state root.");
  try {
    return await fn(actual);
  } finally {
    await rm(actual, { recursive: true });
  }
}
