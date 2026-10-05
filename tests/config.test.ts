import assert from "node:assert/strict";
import { readdir } from "node:fs/promises";
import { test } from "node:test";
import { configuration, modelSecrets, validateRuntime } from "../scripts/lib/config.ts";
import { denials, destinations } from "../scripts/lib/network.ts";
import type { Target } from "../scripts/lib/profiles.ts";

const valid = {
  minSbxVersion: "0.46.0",
  defaultRole: "ReadOnlyRole",
  sessionDurationSeconds: 3600,
  renewWithinSeconds: 900,
  templates: { claude: { tag: "readonly-agent-claude:0.2.0", modelSecret: "anthropic" } },
};

test("every configured agent has a Dockerfile and network hosts, and vice versa", async () => {
  const { runtime, network } = await configuration();
  const agents = Object.keys(runtime.templates).sort();
  const dockerfiles = (await readdir("sandbox"))
    .filter((name) => name.startsWith("Dockerfile."))
    .map((name) => name.slice("Dockerfile.".length))
    .sort();
  assert.deepEqual(dockerfiles, agents);
  assert.deepEqual(Object.keys(network.agents).sort(), agents);
});
test("no configured block covers a host any agent is allowed, in any partition", async () => {
  const { network } = await configuration();
  for (const agent of Object.keys(network.agents))
    for (const partition of [undefined, ...Object.keys(network.awsDomains ?? {})]) {
      const target = partition ? ({ partition } as Target) : undefined;
      assert.doesNotThrow(() => denials(network, destinations(network, agent, target)));
    }
});
test("model secrets come from the templates", () => {
  assert.deepEqual(
    modelSecrets(
      validateRuntime({
        ...valid,
        templates: { ...valid.templates, other: { tag: "readonly-agent-other:0.1.0" } },
      }),
    ),
    ["anthropic"],
  );
});
test("runtime config is validated", () => {
  assert.doesNotThrow(() => validateRuntime(valid));
  for (const [change, field] of [
    [{ defaultRole: undefined }, /defaultRole/],
    [{ sessionDurationSeconds: 600 }, /sessionDurationSeconds/],
    [{ sessionDurationSeconds: 50_000 }, /sessionDurationSeconds/],
    [{ sessionDurationSeconds: "3600" }, /sessionDurationSeconds/],
    [{ renewWithinSeconds: 3600 }, /renewWithinSeconds/],
    [{ renewWithinSeconds: -1 }, /renewWithinSeconds/],
    [{ templates: {} }, /templates/],
    [{ templates: { claude: {} } }, /templates\.claude\.tag/],
    [{ templates: { "Bad-Name": { tag: "x" } } }, /templates key/],
  ] as const)
    assert.throws(() => validateRuntime({ ...valid, ...change }), field);
});
