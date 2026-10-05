import assert from "node:assert/strict";
import { test } from "node:test";
import {
  bridgeProfile,
  mergeProfiles,
  type Profiles,
  parseProfiles,
  type Selection,
  selectTarget,
} from "../scripts/lib/profiles.ts";

// The CLI supplies config/runtime.json's defaultRole when --role is absent.
const select = (profiles: Profiles, profile: string, options: Partial<Selection> = {}) =>
  selectTarget(profiles, profile, { role: "ReadOnlyRole", ...options });

function fixtures(
  target = "workload",
  source = "session-bridge",
  login = "browser-login",
  originalRole = "DeveloperRole",
) {
  return mergeProfiles(
    parseProfiles(
      `[profile ${login}]\nlogin_session = arn:aws:iam::111111111111:user/example\n[profile ${target}]\nregion = us-east-1\n`,
      "config",
    ),
    parseProfiles(
      `[${target}]\nrole_arn = arn:aws:iam::222222222222:role/${originalRole}\nsource_profile = ${source}\nregion = us-west-2\n[${source}]\ncredential_process = aws configure export-credentials --profile ${login} --format process\n`,
      "credentials",
    ),
  );
}
test("generic profiles split across files resolve metadata and immediate source", () => {
  for (const names of [
    ["workload", "session-bridge", "browser-login", "DeveloperRole"],
    ["research-prod", "auth-source", "personal-login", "ops/OperatorRole"],
  ]) {
    const target = select(fixtures(...names), names[0]);
    assert.equal(target.account, "222222222222");
    assert.equal(target.sourceProfile, names[1]);
    assert.equal(target.loginProfile, names[2]);
    assert.equal(target.region, "us-west-2");
    assert.equal(target.roleArn, "arn:aws:iam::222222222222:role/ReadOnlyRole");
  }
});
test("role path, region and source overrides do not modify profiles", () => {
  const profiles = fixtures(),
    before = JSON.stringify([...profiles]);
  const target = select(profiles, "workload", {
    sourceProfile: "browser-login",
    role: "agents/RestrictedRole",
    region: "eu-west-1",
  });
  assert.equal(target.sourceProfile, "browser-login");
  assert.equal(target.roleArn, "arn:aws:iam::222222222222:role/agents/RestrictedRole");
  assert.equal(target.region, "eu-west-1");
  assert.equal(JSON.stringify([...profiles]), before);
});
test("intermediate roles are validated but not skipped", () => {
  const profiles = fixtures();
  profiles.set("intermediate", {
    role_arn: "arn:aws:iam::333333333333:role/Broker",
    source_profile: "session-bridge",
  });
  profiles.get("workload")!.source_profile = "intermediate";
  const target = select(profiles, "workload");
  assert.equal(target.sourceProfile, "intermediate");
  assert.equal(target.loginProfile, "browser-login");
});
test("rejects cycles, self-source overrides and bridges back through target", () => {
  assert.throws(() => select(fixtures(), "workload", { sourceProfile: "workload" }), /cyclic/);
  const profiles = fixtures();
  profiles.get("session-bridge")!.credential_process =
    "aws configure export-credentials --profile workload --format process";
  assert.throws(() => select(profiles, "workload"), /cyclic/);
});
test("a role is required", () => {
  assert.throws(() => selectTarget(fixtures(), "workload", { role: "" }), /defaultRole/);
});
test("unsupported metadata never activates the target as a fallback", () => {
  const profiles = fixtures();
  delete profiles.get("workload")!.role_arn;
  assert.throws(() => select(profiles, "workload"), /role_arn/);
  assert.throws(() => select(fixtures(), "missing"), /does not exist/);
  assert.throws(
    () => select(fixtures(), "workload", { role: "arn:aws:iam::222222222222:role/Admin" }),
    /not an ARN/,
  );
  assert.throws(
    () => select(fixtures(), "workload", { sourceProfile: "missing" }),
    /does not exist/,
  );
});
test("rejects static credentials only in the selected source chain", () => {
  const profiles = fixtures();
  profiles.set("unrelated", { aws_access_key_id: "EXAMPLE_ONLY" });
  assert.doesNotThrow(() => select(profiles, "workload"));
  profiles.get("browser-login")!.aws_access_key_id = "EXAMPLE_ONLY";
  assert.throws(() => select(profiles, "workload"), /Static credentials/);
});
test("INI metadata handles BOM, CRLF, comments, nested settings and quoted profile names", () => {
  const profiles = parseProfiles(
    '\uFEFF[profile "test-name"] # comment\r\nrole_arn = arn:aws:iam::222222222222:role/Dev\r\ns3 =\r\n  max_concurrent_requests = 20\r\nregion = us-west-2\r\n[services ignored]\r\nfoo = bar',
    "config",
  );
  assert.equal(profiles.get("test-name")!.region, "us-west-2");
  assert.equal(profiles.size, 1);
  assert.equal(profiles.get("test-name")!.max_concurrent_requests, undefined);
  assert.throws(() => parseProfiles("[x]\na=1\na=2", "credentials"), /Duplicate/);
});
test("login bridge accepts flag order and quoted executable paths", () => {
  assert.equal(
    bridgeProfile(
      '"C:\\Program Files\\AWSCLIV2\\aws.exe" configure export-credentials --format process --profile "browser login"',
    ),
    "browser login",
  );
  assert.equal(bridgeProfile("custom-provider --token secret"), undefined);
});
test("validates partition/region and replaces the original role path", () => {
  const profiles = fixtures();
  profiles.get("workload")!.role_arn = "arn:aws-cn:iam::222222222222:role/path/Developer";
  assert.throws(() => select(profiles, "workload"), /partition/);
  assert.equal(
    select(profiles, "workload", { region: "cn-north-1" }).roleArn,
    "arn:aws-cn:iam::222222222222:role/ReadOnlyRole",
  );
});
