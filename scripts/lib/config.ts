import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { NetworkConfig } from "./network.ts";

export const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

export interface Template {
  tag: string;
  // sbx service secret for the agent's model provider, managed by sbx itself.
  modelSecret?: string;
}
export interface Runtime {
  minSbxVersion: string;
  // Restricted role assumed when --role is not given.
  defaultRole: string;
  // Requested AWS session length. STS caps chained role sessions at one hour.
  sessionDurationSeconds: number;
  // Resume renews the AWS session when less than this remains.
  renewWithinSeconds: number;
  // One template per supported agent; the keys are the agent names.
  templates: Record<string, Template>;
}

const integer = (value: unknown, min: number, max: number) =>
  Number.isInteger(value) && (value as number) >= min && (value as number) <= max;

export function validateRuntime(value: unknown): Runtime {
  const runtime = value as Runtime;
  const problem = (field: string, rule: string) =>
    new Error(`config/runtime.json: ${field} must be ${rule}.`);
  if (typeof runtime?.minSbxVersion !== "string" || !/^\d+\.\d+\.\d+$/.test(runtime.minSbxVersion))
    throw problem("minSbxVersion", "a version like 1.2.3");
  if (typeof runtime.defaultRole !== "string" || !runtime.defaultRole)
    throw problem("defaultRole", "an IAM role name or path");
  // STS AssumeRole accepts 15 minutes to 12 hours.
  if (!integer(runtime.sessionDurationSeconds, 900, 43_200))
    throw problem("sessionDurationSeconds", "an integer from 900 to 43200");
  if (!integer(runtime.renewWithinSeconds, 0, runtime.sessionDurationSeconds - 1))
    throw problem("renewWithinSeconds", "a non-negative integer below sessionDurationSeconds");
  const templates = Object.entries(runtime.templates ?? {});
  if (!templates.length) throw problem("templates", "a non-empty object");
  for (const [agent, template] of templates) {
    if (!/^[a-z0-9]+$/.test(agent)) throw problem(`templates key ${agent}`, "lowercase a-z0-9");
    if (typeof template?.tag !== "string" || !template.tag)
      throw problem(`templates.${agent}.tag`, "an image tag");
    if (template.modelSecret !== undefined && typeof template.modelSecret !== "string")
      throw problem(`templates.${agent}.modelSecret`, "a string");
  }
  return runtime;
}

export async function configuration(): Promise<{ runtime: Runtime; network: NetworkConfig }> {
  const [runtime, network] = await Promise.all(
    ["runtime", "network-policy"].map((name) =>
      readFile(join(root, "config", `${name}.json`), "utf8"),
    ),
  );
  return { runtime: validateRuntime(JSON.parse(runtime)), network: JSON.parse(network) };
}

export async function agents(): Promise<string[]> {
  return Object.keys((await configuration()).runtime.templates);
}

// Model authentication stays managed by sbx. Every agent's model secret is
// expected for every agent: the sbx proxy applies each only on that provider's hosts.
export function modelSecrets(runtime: Runtime): string[] {
  return Object.values(runtime.templates).flatMap((template) => template.modelSecret ?? []);
}
