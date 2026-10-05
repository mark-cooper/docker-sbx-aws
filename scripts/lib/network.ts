import type { Target } from "./profiles.ts";

export interface NetworkConfig {
  // Model/auth hosts per agent.
  agents: Record<string, string[]>;
  // Other hosts every agent may reach, such as AWS documentation.
  hosts?: string[];
  // AWS domains per partition, usually sbx multi-label wildcards (**.amazonaws.com).
  awsDomains?: Record<string, string[]>;
}
export interface Rule {
  resource_type: string;
  decision: string;
  resources: string[];
  actions: string[];
  status: string;
  applies_to?: string;
}

// AWS domains are added only for a sandbox with an AWS session (a target).
export function destinations(config: NetworkConfig, agent: string, target?: Target): string[] {
  const hosts = [
    ...(config.agents[agent] ?? []),
    ...(config.hosts ?? []),
    ...((target && config.awsDomains?.[target.partition]) ?? []),
  ];
  // DNS names, optionally with one leading sbx wildcard label (*. or **.) for a
  // reviewed domain. No bare wildcards, schemes, ports, IPs or CIDRs.
  if (
    !hosts.length ||
    hosts.some((host) => !/^(?:\*\*?\.)?(?:[a-z0-9-]+\.)+[a-z0-9-]+$/.test(host))
  )
    throw new Error(
      "Network policy must contain DNS hostnames or *./**. domain wildcards, without schemes or ports.",
    );
  return [...new Set(hosts)].map((host) => `${host}:443`);
}

// Concrete destinations for live checks: every exact entry, and for each
// wildcard a nested name it must admit.
export function probes(allowed: string[]): string[] {
  return allowed.map((entry) =>
    entry.replace(/^\*\*\./, "probe.example.").replace(/^\*\./, "probe."),
  );
}
// Cloud instance metadata would hand the agent the host's own credentials,
// bypassing the restricted role, so it must stay blocked whatever the
// developer's own policy allows.
export const blockedProbes = ["169.254.169.254:80", "[fd00:ec2::254]:80"];

// Rules that can affect the given sandbox, or any new sandbox when omitted.
// Rules scoped to other sandboxes are dropped before audit, so their allows
// cannot fail this sandbox. Rules without a sandbox scope are always kept.
function policyRules(value: unknown, sandbox?: string): Rule[] {
  const data = value as { rules?: Rule[] };
  if (!Array.isArray(data?.rules)) throw new Error("Unsupported sbx policy JSON schema.");
  return data.rules.filter(
    (rule) =>
      typeof rule.applies_to !== "string" ||
      !rule.applies_to.startsWith("sandbox:") ||
      rule.applies_to === `sandbox:${sandbox}`,
  );
}

// Approved entries the sandbox's policy does not yet allow. The project's
// allows are layered on the developer's own policy, which is never narrowed.
// Existing rules are never duplicated.
export function missingAllows(value: unknown, allowed: string[], sandbox?: string): string[] {
  const allows = new Set(
    policyRules(value, sandbox)
      .filter((rule) => rule.status === "active" && rule.decision === "allow")
      .flatMap((rule) => (Array.isArray(rule.resources) ? rule.resources : [])),
  );
  return allowed.filter((resource) => !allows.has(resource));
}

// A rule admitting every destination removes the proxy as a control.
const everything = (resource: string) =>
  ["*", "**", "0.0.0.0/0", "::/0"].includes(resource.replace(/:(\d+|\*)$/, ""));

// Any allows the developer's policy grants are accepted, except one that
// admits every destination. Rules of an unknown shape or status fail closed.
export function auditPolicy(value: unknown, sandbox?: string): void {
  for (const rule of policyRules(value, sandbox)) {
    if (!["active", "inactive"].includes(rule.status))
      throw new Error("Unknown policy status; refusing to assume enforcement.");
    if (rule.status === "inactive") continue;
    if (rule.resource_type !== "network")
      throw new Error("Unexpected resource type in network policy response.");
    if (
      !["allow", "deny"].includes(rule.decision) ||
      !Array.isArray(rule.resources) ||
      !Array.isArray(rule.actions)
    )
      throw new Error("Unsupported network policy rule.");
    if (rule.decision === "allow" && rule.resources.some(everything))
      throw new Error(
        "Effective sbx network policy allows every destination. Remove the allow-all rule (the recommended sbx policy is balanced); the sandbox proxy must still block instance metadata.",
      );
  }
}
