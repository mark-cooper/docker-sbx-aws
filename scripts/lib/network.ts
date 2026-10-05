import type { Target } from "./profiles.ts";

export interface NetworkConfig {
  // Model/auth hosts per agent.
  agents: Record<string, string[]>;
  // Other hosts every agent may reach, such as AWS documentation.
  allowedHosts?: string[];
  // Hosts denied to every agent on every port, even where the developer's own
  // policy allows them.
  blockedHosts?: string[];
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

// DNS names, optionally with one leading sbx wildcard label (*. or **.) for a
// reviewed domain. No bare wildcards, schemes, ports, IPs or CIDRs: the last
// label needs a letter, so a dotted IPv4 address is not mistaken for a name.
function checkHosts(hosts: string[]): void {
  if (hosts.some((host) => !/^(?:\*\*?\.)?(?:[a-z0-9-]+\.)+[a-z0-9-]*[a-z][a-z0-9-]*$/.test(host)))
    throw new Error(
      "Network policy must contain DNS hostnames or *./**. domain wildcards, without schemes or ports.",
    );
}

// AWS domains are added only for a sandbox with an AWS session (a target).
export function destinations(config: NetworkConfig, agent: string, target?: Target): string[] {
  const hosts = [
    ...(config.agents[agent] ?? []),
    ...(config.allowedHosts ?? []),
    ...((target && config.awsDomains?.[target.partition]) ?? []),
  ];
  if (!hosts.length) throw new Error("Network policy must allow at least one host.");
  checkHosts(hosts);
  return [...new Set(hosts)].map((host) => `${host}:443`);
}

// Whether an sbx pattern admits a name: exactly, one label under *., or the
// domain and any subdomain under **.
function covers(pattern: string, name: string): boolean {
  if (pattern.startsWith("**.")) {
    const domain = pattern.slice(3);
    return name === domain || name.endsWith(`.${domain}`);
  }
  if (pattern.startsWith("*.")) {
    const domain = pattern.slice(2);
    return name.endsWith(`.${domain}`) && !name.slice(0, -domain.length - 1).includes(".");
  }
  return pattern === name;
}

// Metadata plus the configured blocks. A block may carve a host out of an
// allowed wildcard, but must not cover an allowed entry: sbx would silently
// let the deny win.
export function denials(config: NetworkConfig, allowed: string[]): string[] {
  const hosts = config.blockedHosts ?? [];
  checkHosts(hosts);
  const names = allowed.map((entry) => entry.replace(/:443$/, ""));
  const conflict = hosts.find((host) => names.some((name) => covers(host, name)));
  if (conflict) throw new Error(`Blocked host ${conflict} would deny an allowed host.`);
  return [...metadataHosts, ...new Set(hosts)];
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
// developer's own policy allows. Each sandbox gets an explicit deny (all
// ports), so a pending approval can never be granted for it. sbx takes a
// bare IPv4 address for every port, but an IPv6 one only as a /128 CIDR, and
// lists each exactly as given.
export const metadataHosts = ["169.254.169.254", "fd00:ec2::254/128"];
const metadataProbes = metadataHosts.map((host) =>
  host.includes(":") ? `[${host.replace(/\/128$/, "")}]:80` : `${host}:80`,
);
// Destinations each deny must refuse: metadata over HTTP, and the configured
// blocks on the port the developer's allows use.
export function deniedProbes(denied: string[]): string[] {
  const blocks = denied.filter((host) => !metadataHosts.includes(host));
  return [...metadataProbes, ...probes(blocks.map((host) => `${host}:443`))];
}

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

// Resources the sandbox's policy does not yet allow (or deny). The project's
// rules are layered on the developer's own policy; only metadata is ever
// denied. Existing rules are never duplicated.
export function missingRules(
  value: unknown,
  decision: "allow" | "deny",
  resources: string[],
  sandbox?: string,
): string[] {
  const present = new Set(
    policyRules(value, sandbox)
      .filter((rule) => rule.status === "active" && rule.decision === decision)
      .flatMap((rule) => (Array.isArray(rule.resources) ? rule.resources : [])),
  );
  return resources.filter((resource) => !present.has(resource));
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
