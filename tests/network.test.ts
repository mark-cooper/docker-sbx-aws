import assert from "node:assert/strict";
import { test } from "node:test";
import {
  auditPolicy,
  blockedProbes,
  destinations,
  policyChanges,
  probes,
  toleratedGlobalAllows,
} from "../scripts/lib/network.ts";
import type { Target } from "../scripts/lib/profiles.ts";

const allow = (resources: string[]) => ({
  resource_type: "network",
  status: "active",
  decision: "allow",
  actions: ["net:connect:tcp"],
  resources,
});
test("rejects wildcard, UDP, unapproved endpoints and unknown policy schema", () => {
  for (const resource of ["**", "*.amazonaws.com:443", "github.com:443", "api.example.com:80"])
    assert.throws(
      () => auditPolicy({ rules: [allow([resource])] }, ["api.example.com:443"]),
      /outside/,
    );
  assert.throws(
    () =>
      auditPolicy(
        { rules: [{ ...allow(["api.example.com:443"]), actions: ["net:connect:udp"] }] },
        ["api.example.com:443"],
      ),
    /outside/,
  );
  assert.throws(
    () => auditPolicy({ rules: [{ ...allow(["**"]), status: "unknown" }] }, []),
    /Unknown policy status/,
  );
  assert.throws(() => auditPolicy({}, []), /schema/);
});
test("accepts exact TCP destinations, restrictive denies and inactive broad rules", () => {
  auditPolicy(
    {
      rules: [
        allow(["api.example.com:443"]),
        { ...allow(["**"]), status: "inactive" },
        { ...allow(["169.254.169.254"]), decision: "deny" },
      ],
    },
    ["api.example.com:443"],
  );
});
test("accepts a kit endpoint only after a matching scoped deny; wildcard subtraction remains forbidden", () => {
  auditPolicy(
    { rules: [allow(["github.com:443"]), { ...allow(["github.com:443"]), decision: "deny" }] },
    [],
  );
  assert.throws(
    () =>
      auditPolicy(
        {
          rules: [
            allow(["*.example.com:443"]),
            { ...allow(["*.example.com:443"]), decision: "deny" },
          ],
        },
        [],
      ),
    /outside/,
  );
});
test("builds agent, shared and partition AWS domains; rejects malformed entries", () => {
  const config = {
    agents: { claude: ["api.anthropic.com"] },
    hosts: ["docs.aws.amazon.com"],
    awsDomains: { aws: ["**.amazonaws.com", "**.api.aws"], "aws-cn": ["**.amazonaws.com.cn"] },
  };
  assert.deepEqual(
    destinations(config, "claude", { region: "us-west-2", partition: "aws" } as Target),
    ["api.anthropic.com:443", "docs.aws.amazon.com:443", "**.amazonaws.com:443", "**.api.aws:443"],
  );
  assert.deepEqual(
    destinations(config, "claude", { region: "cn-north-1", partition: "aws-cn" } as Target),
    ["api.anthropic.com:443", "docs.aws.amazon.com:443", "**.amazonaws.com.cn:443"],
  );
  const target = { region: "us-west-2", partition: "aws" } as Target;
  for (const bad of [
    "*",
    "**",
    "**.com.*",
    "a.*.example.com",
    "https://example.com",
    "example.com:443",
    "10.0.0.0/8",
  ])
    assert.throws(() => destinations({ agents: { claude: [bad] } }, "claude", target), /DNS/);
});
test("GitHub API hosts are added only when the caller confirms a stored github secret", () => {
  const config = { agents: { claude: ["api.anthropic.com"] }, github: ["api.github.com"] };
  const target = { region: "us-west-2", partition: "aws" } as Target;
  assert.deepEqual(destinations(config, "claude", target), ["api.anthropic.com:443"]);
  assert.deepEqual(destinations(config, "claude", target, { github: false }), [
    "api.anthropic.com:443",
  ]);
  assert.deepEqual(destinations(config, "claude", target, { github: true }), [
    "api.anthropic.com:443",
    "api.github.com:443",
  ]);
});
test("a standing global allow for a tolerated host passes the audit even without a per-launch secret", () => {
  assert.deepEqual(toleratedGlobalAllows, ["api.github.com:443"]);
  // Unlike an arbitrary global allow, this one is expected ambient policy from
  // the dedicated setup's fresh-install commands, not launcher drift.
  auditPolicy({ rules: [allow(["api.github.com:443"])] }, []);
  auditPolicy({ rules: [allow(["api.github.com:443"])] }, ["api.github.com:443"]);
  // Only the exact tolerated entry is exempt; a lookalike or a different host
  // still trips the audit like any other unexplained global allow.
  for (const resource of ["github.com:443", "api.github.com:80", "evilapi.github.com:443"])
    assert.throws(() => auditPolicy({ rules: [allow([resource])] }, []), /outside/);
});
test("approved wildcards admit hosts beneath them; broader wildcards stay forbidden", () => {
  const allowed = ["**.amazonaws.com:443", "*.example.org:443"];
  // The literal approved wildcard, and exact hosts beneath it (for example an
  // older sandbox's per-service rules), pass the audit.
  auditPolicy(
    {
      rules: [
        allow([
          "**.amazonaws.com:443",
          "sts.us-west-2.amazonaws.com:443",
          "amazonaws.com:443",
          "a.example.org:443",
        ]),
      ],
    },
    allowed,
  );
  for (const resource of [
    "**:443",
    "**.com:443",
    "*.amazonaws.com.evil.com:443",
    "a.b.example.org:443",
    "sts.us-west-2.amazonaws.com:80",
    "evilamazonaws.com:443",
  ])
    assert.throws(() => auditPolicy({ rules: [allow([resource])] }, allowed), /outside/);
  // Hosts the wildcard admits are neither re-added nor denied; others are denied.
  assert.deepEqual(
    policyChanges(
      {
        rules: [
          allow([
            "**.amazonaws.com:443",
            "sts.us-west-2.amazonaws.com:443",
            "downloads.claude.ai:443",
          ]),
        ],
      },
      allowed,
    ),
    { allow: ["*.example.org:443"], deny: ["downloads.claude.ai:443"] },
  );
});
test("live probes cover each wildcard and its lookalikes", () => {
  const allowed = ["docs.aws.amazon.com:443", "**.amazonaws.com:443"];
  assert.deepEqual(probes(allowed), ["docs.aws.amazon.com:443", "probe.example.amazonaws.com:443"]);
  const blocked = blockedProbes(allowed);
  for (const probe of [
    "example.com:443",
    "169.254.169.254:80",
    "amazonaws.com.example.com:443",
    "exampleamazonaws.com:443",
    "amazonaws.com:80",
  ])
    assert.ok(blocked.includes(probe), probe);
});
test("policy changes add missing allows and deny other exact allows exactly once", () => {
  const rules = [
    allow(["api.example.com:443", "github.com:443", "kit.example.com:443", "*.example.com:443"]),
    { ...allow(["registry.example.com:443"]), status: "inactive" },
    // Already denied on an earlier launch or resume: not denied again.
    { ...allow(["kit.example.com:443"]), decision: "deny" },
  ];
  assert.deepEqual(policyChanges({ rules }, ["api.example.com:443", "logs.example.com:443"]), {
    allow: ["logs.example.com:443"],
    deny: ["github.com:443"],
  });
  assert.throws(() => policyChanges({}, []), /schema/);
});
test("rules scoped to other sandboxes neither fail nor protect this sandbox", () => {
  const scoped = (sandbox: string, rule: ReturnType<typeof allow>) => ({
    ...rule,
    applies_to: `sandbox:${sandbox}`,
  });
  const other = scoped("ro-claude-000000000000", allow(["api.anthropic.com:443"]));
  // Before creation, another session's allowlist does not apply to a new sandbox.
  auditPolicy({ rules: [other] }, ["api.openai.com:443"]);
  auditPolicy({ rules: [other] }, ["api.openai.com:443"], "ro-codex-000000000000");
  // The same rule applies when auditing its own sandbox.
  assert.throws(
    () => auditPolicy({ rules: [other] }, ["api.openai.com:443"], "ro-claude-000000000000"),
    /outside/,
  );
  // A deny scoped to another sandbox cannot neutralize this sandbox's allow.
  const mine = scoped("ro-codex-000000000000", allow(["github.com:443"]));
  const foreignDeny = scoped("ro-claude-000000000000", {
    ...allow(["github.com:443"]),
    decision: "deny",
  });
  assert.throws(
    () => auditPolicy({ rules: [mine, foreignDeny] }, [], "ro-codex-000000000000"),
    /outside/,
  );
  // Unscoped (global) allows always count.
  assert.throws(() => auditPolicy({ rules: [allow(["github.com:443"])] }, []), /outside/);
  assert.deepEqual(policyChanges({ rules: [other, mine] }, [], "ro-codex-000000000000"), {
    allow: [],
    deny: ["github.com:443"],
  });
});
