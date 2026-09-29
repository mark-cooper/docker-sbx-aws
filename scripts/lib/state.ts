import { mkdir, mkdtemp, readFile, realpath, rename, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, join, relative, resolve } from "node:path";
import type { Target } from "./profiles.ts";

export interface State {
  version: 1;
  name: string;
  agent: string;
  target: Target;
  // Absent for an empty workspace.
  project?: string;
  direct: boolean;
  workspace?: string;
  baseFingerprint?: string;
  collectedFingerprint?: string;
  collectedBundle?: string;
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
export function validateName(name: string): void {
  if (!new RegExp(`^ro-(${agents.join("|")})-[a-f0-9]{12}$`).test(name))
    throw new Error("Not a managed sandbox name.");
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
  try {
    state = JSON.parse(await readFile(join(stateRoot(), "sessions", `${name}.json`), "utf8"));
  } catch {
    throw new Error("Managed session metadata not found or invalid.");
  }
  if (state.name !== name || state.version !== 1 || !agents.includes(state.agent))
    throw new Error("Invalid managed session metadata.");
  return state;
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
