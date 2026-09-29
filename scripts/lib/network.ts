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

export function destinations(config: NetworkConfig, agent: string, target: Target): string[] {
  const hosts = [
    ...(config.agents[agent] ?? []),
    ...(config.hosts ?? []),
    ...(config.awsDomains?.[target.partition] ?? []),
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

// An exact host:port destination, never a wildcard or CIDR.
const exact = (resource: string) => /^[a-z0-9.-]+:\d+$/.test(resource);

// Whether an allowlist entry admits an exact host:port, with sbx semantics:
// "*." matches one label, "**." any number of labels including none.
function admits(entry: string, resource: string): boolean {
  if (entry === resource) return true;
  const wildcard = /^(\*\*?)\.(.+)$/.exec(entry);
  if (!wildcard || !exact(resource)) return false;
  const [, stars, suffix] = wildcard;
  if (stars === "**" && resource === suffix) return true;
  if (!resource.endsWith(`.${suffix}`)) return false;
  const prefix = resource.slice(0, -suffix.length - 1);
  return stars === "**" || !prefix.includes(".");
}
const covered = (resource: string, allowed: string[]) =>
  allowed.some((entry) => admits(entry, resource));

// Concrete destinations for live checks: every exact entry, and for each
// wildcard a nested name it must admit.
export function probes(allowed: string[]): string[] {
  return allowed.map((entry) =>
    entry.replace(/^\*\*\./, "probe.example.").replace(/^\*\./, "probe."),
  );
}
// Destinations that must stay blocked: other internet hosts, metadata and
// private addresses, and lookalikes of every allowed domain.
export function blockedProbes(allowed: string[]): string[] {
  const lookalikes = allowed
    .filter((entry) => entry.startsWith("*"))
    .flatMap((entry) => {
      const domain = entry.replace(/^\*\*?\./, "").replace(/:\d+$/, "");
      return [`${domain}.example.com:443`, `example${domain}:443`, `${domain}:80`];
    });
  return [
    "example.com:443",
    "169.254.169.254:80",
    "127.0.0.1:443",
    "10.0.0.1:443",
    "192.168.1.1:443",
    "[::1]:443",
    ...lookalikes,
  ].filter((probe) => !covered(probe, allowed));
}

// Rules that can affect the given sandbox, or any new sandbox when omitted.
// Rules scoped to other sandboxes are dropped before audit, so their allows
// cannot fail this sandbox and their denies cannot neutralize its allows.
// Rules without a sandbox scope are always kept.
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

function activeResources(rules: Rule[], decision: "allow" | "deny"): Set<string> {
  return new Set(
    rules
      .filter((rule) => rule.status === "active" && rule.decision === decision)
      .flatMap((rule) => (Array.isArray(rule.resources) ? rule.resources : [])),
  );
}

// Rules needed to bring a sandbox's policy to exactly the allowlist: approved
// entries not yet allowed, and other exact allows (agent-kit endpoints, or
// hosts since removed from the list) not yet denied. Exact allows already
// admitted by an approved wildcard are left alone. Unapproved wildcards are
// left for auditPolicy to reject. Existing rules are never duplicated.
export function policyChanges(
  value: unknown,
  allowed: string[],
  sandbox?: string,
): { allow: string[]; deny: string[] } {
  const rules = policyRules(value, sandbox);
  const allows = activeResources(rules, "allow");
  const denies = activeResources(rules, "deny");
  return {
    allow: allowed.filter((resource) => !allows.has(resource)),
    deny: [...allows].filter(
      (resource) => !covered(resource, allowed) && exact(resource) && !denies.has(resource),
    ),
  };
}

// Conservative audit: every effective allow must be an approved entry, or an
// exact host an approved wildcard admits. Only an explicit deny of the
// identical resource can neutralize an extra exact allow. A wildcard allow is
// accepted only when it is literally an approved entry; never try to prove a
// broader wildcard safe with pattern subtraction.
export function auditPolicy(value: unknown, allowed: string[], sandbox?: string): void {
  const rules = policyRules(value, sandbox);
  for (const rule of rules) {
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
    if (rule.decision === "deny") continue;
    const blocked = (resource: string) =>
      exact(resource) &&
      rules.some(
        (deny) =>
          deny.status === "active" &&
          deny.decision === "deny" &&
          Array.isArray(deny.resources) &&
          deny.resources.includes(resource) &&
          Array.isArray(deny.actions) &&
          rule.actions.every((action) => deny.actions.includes(action)),
      );
    if (
      !rule.actions.length ||
      rule.resources.some(
        (resource) =>
          !blocked(resource) &&
          (!covered(resource, allowed) ||
            rule.actions.some((action) => action !== "net:connect:tcp")),
      )
    ) {
      throw new Error(
        "Effective sbx network policy allows destinations outside this project's exact allowlist. Use a dedicated, deny-all sbx setup and remove broad global/kit allows. The launcher never changes global policies.",
      );
    }
  }
}
