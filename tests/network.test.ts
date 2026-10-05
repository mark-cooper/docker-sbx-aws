import assert from "node:assert/strict";
import { test } from "node:test";
import {
  auditPolicy,
  blockedProbes,
  destinations,
  missingAllows,
  probes,
} from "../scripts/lib/network.ts";
import type { Target } from "../scripts/lib/profiles.ts";

const allow = (resources: string[]) => ({
  resource_type: "network",
  status: "active",
  decision: "allow",
  actions: ["net:connect:tcp"],
  resources,
});
test("accepts the developer's other allows but never allow-all", () => {
  auditPolicy({
    rules: [
      allow(["github.com:443", "*.npmjs.org:443", "registry.example.com:443"]),
      { ...allow(["**"]), status: "inactive" },
      { ...allow(["**"]), decision: "deny" },
    ],
  });
  for (const resource of ["*", "**", "**:443", "*:443", "0.0.0.0/0", "::/0"])
    assert.throws(() => auditPolicy({ rules: [allow([resource])] }), /every destination/);
});
test("rejects unknown policy status, rule shape and schema", () => {
  assert.throws(
    () => auditPolicy({ rules: [{ ...allow(["github.com:443"]), status: "unknown" }] }),
    /Unknown policy status/,
  );
  assert.throws(
    () => auditPolicy({ rules: [{ ...allow(["github.com:443"]), resource_type: "fs" }] }),
    /resource type/,
  );
  assert.throws(
    () => auditPolicy({ rules: [{ ...allow(["github.com:443"]), decision: "ask" }] }),
    /Unsupported/,
  );
  assert.throws(() => auditPolicy({}), /schema/);
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
test("live probes cover each exact host and wildcard; metadata must stay blocked", () => {
  const allowed = ["docs.aws.amazon.com:443", "**.amazonaws.com:443", "*.example.org:443"];
  assert.deepEqual(probes(allowed), [
    "docs.aws.amazon.com:443",
    "probe.example.amazonaws.com:443",
    "probe.example.org:443",
  ]);
  assert.deepEqual(blockedProbes, ["169.254.169.254:80", "[fd00:ec2::254]:80"]);
});
test("missing allows are added exactly once and nothing is denied", () => {
  const rules = [
    allow(["api.example.com:443", "github.com:443"]),
    { ...allow(["logs.example.com:443"]), status: "inactive" },
  ];
  assert.deepEqual(missingAllows({ rules }, ["api.example.com:443", "logs.example.com:443"]), [
    "logs.example.com:443",
  ]);
  assert.throws(() => missingAllows({}, []), /schema/);
});
test("rules scoped to other sandboxes are ignored", () => {
  const scoped = (sandbox: string, rule: ReturnType<typeof allow>) => ({
    ...rule,
    applies_to: `sandbox:${sandbox}`,
  });
  const other = scoped("ro-claude-000000000000", allow(["**"]));
  // Before creation, another sandbox's rules do not apply to a new sandbox.
  auditPolicy({ rules: [other] });
  auditPolicy({ rules: [other] }, "ro-codex-000000000000");
  // The same rule applies when auditing its own sandbox.
  assert.throws(() => auditPolicy({ rules: [other] }, "ro-claude-000000000000"), /every/);
  // Another sandbox's allow does not satisfy this sandbox's allowlist.
  const mine = scoped("ro-codex-000000000000", allow(["api.openai.com:443"]));
  const theirs = scoped("ro-claude-000000000000", allow(["api.anthropic.com:443"]));
  assert.deepEqual(
    missingAllows(
      { rules: [mine, theirs] },
      ["api.openai.com:443", "api.anthropic.com:443"],
      "ro-codex-000000000000",
    ),
    ["api.anthropic.com:443"],
  );
});
