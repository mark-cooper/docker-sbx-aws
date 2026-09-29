import assert from "node:assert/strict";
import { test } from "node:test";
import { assumeRestrictedRole, validateLifetime } from "../scripts/lib/aws.ts";
import type { Runner, RunOptions } from "../scripts/lib/process.ts";
import { awsEnvironment, hostEnvironment } from "../scripts/lib/process.ts";
import type { Target } from "../scripts/lib/profiles.ts";

const target: Target = {
  profile: "workload",
  sourceProfile: "auth-source",
  loginProfile: "browser-login",
  account: "222222222222",
  partition: "aws",
  region: "us-west-2",
  role: "agents/ReadOnlyRole",
  roleArn: "arn:aws:iam::222222222222:role/agents/ReadOnlyRole",
};
const env = {
  PATH: "tools",
  AWS_ACCESS_KEY_ID: "HOST_KEY_MUST_NOT_LEAK",
  AWS_SECRET_ACCESS_KEY: "HOST_SECRET_MUST_NOT_LEAK",
  AWS_PROFILE: "admin",
  AWS_ENDPOINT_URL: "https://attacker.invalid",
  AWS_CONFIG_FILE: "example-config",
  GH_TOKEN: "HOST_GITHUB_TOKEN",
  NODE_OPTIONS: "--require attacker.js",
};
const credentials = () => ({
  AccessKeyId: "ASIA_EXAMPLE_ONLY",
  SecretAccessKey: "EXAMPLE_SECRET",
  SessionToken: "EXAMPLE_TOKEN",
  Expiration: new Date(Date.now() + 3600_000).toISOString(),
});
test("only immediate source is authenticated; issued session is independently verified", async () => {
  const calls: { args: string[]; options: RunOptions }[] = [];
  let identity = {};
  const run: Runner = async (_cmd, args, options = {}) => {
    calls.push({ args, options });
    assert.ok(!args.includes("workload"));
    let result: unknown;
    if (args[1] === "assume-role") {
      const name = args[args.indexOf("--role-session-name") + 1];
      identity = {
        Account: target.account,
        Arn: `arn:aws:sts::${target.account}:assumed-role/ReadOnlyRole/${name}`,
        UserId: `AROEXAMPLE:${name}`,
      };
      result = {
        Credentials: credentials(),
        AssumedRoleUser: {
          Arn: (identity as { Arn: string }).Arn,
          AssumedRoleId: (identity as { UserId: string }).UserId,
        },
      };
    } else if (args.includes("--profile"))
      result = {
        Account: "111111111111",
        Arn: "arn:aws:iam::111111111111:user/example",
        UserId: "AIDAEXAMPLE",
      };
    else result = identity;
    return { stdout: JSON.stringify(result), stderr: "", code: 0 };
  };
  const session = await assumeRestrictedRole(target, run, env);
  assert.equal(calls.length, 3);
  assert.equal(calls[1].args[calls[1].args.indexOf("--profile") + 1], "auth-source");
  assert.equal(calls[1].args[calls[1].args.indexOf("--role-arn") + 1], target.roleArn);
  assert.equal(calls[0].options.env!.AWS_ACCESS_KEY_ID, undefined);
  assert.equal(calls[0].options.env!.AWS_ENDPOINT_URL, undefined);
  assert.equal(calls[2].options.env!.AWS_ACCESS_KEY_ID, "ASIA_EXAMPLE_ONLY");
  assert.equal(calls[2].options.env!.AWS_PROFILE, undefined);
  assert.equal(calls[2].options.env!.GH_TOKEN, undefined);
  assert.equal(session.identity.Account, target.account);
  assert.ok(!JSON.stringify(calls.map((c) => c.args)).includes("EXAMPLE_SECRET"));
  assert.equal(env.AWS_ACCESS_KEY_ID, "HOST_KEY_MUST_NOT_LEAK");
});
test("denied assumption never falls back or repeats secret-bearing subprocess output", async () => {
  const calls: string[][] = [];
  const run: Runner = async (_cmd, args) => {
    calls.push(args);
    return args[1] === "assume-role"
      ? { code: 1, stdout: "EXAMPLE_SECRET", stderr: "HOST_KEY_MUST_NOT_LEAK" }
      : {
          code: 0,
          stdout: JSON.stringify({ Account: "111111111111", Arn: "source", UserId: "source-id" }),
          stderr: "",
        };
  };
  await assert.rejects(assumeRestrictedRole(target, run, env), (error) => {
    assert.match(String(error), /Direct restricted-role assumption/);
    assert.match(String(error), /browser-login/);
    assert.doesNotMatch(String(error), /EXAMPLE_SECRET|HOST_KEY_MUST_NOT_LEAK/);
    return true;
  });
  assert.equal(calls.length, 2);
  assert.ok(calls.every((args) => !args.includes("workload")));
});
test("identity mismatch prevents using returned credentials", async () => {
  const run: Runner = async (_cmd, args) => ({
    code: 0,
    stderr: "",
    stdout: JSON.stringify(
      args[1] === "assume-role"
        ? {
            Credentials: credentials(),
            AssumedRoleUser: {
              Arn: "arn:aws:sts::333333333333:assumed-role/Administrator/other",
              AssumedRoleId: "other",
            },
          }
        : { Account: "111111111111", Arn: "source", UserId: "source-id" },
    ),
  });
  await assert.rejects(assumeRestrictedRole(target, run, env), /unexpected role identity/);
});
test("expiry rejects malformed, expired and nearly expired sessions", () => {
  for (const expiry of [
    "bad",
    new Date(0).toISOString(),
    new Date(Date.now() + 60_000).toISOString(),
  ])
    assert.throws(() => validateLifetime(expiry), /five minutes/);
});
test("child environments omit unrelated tokens and injection settings", () => {
  assert.deepEqual(hostEnvironment(env), { PATH: "tools" });
  const clean = awsEnvironment(env);
  assert.equal(clean.AWS_CONFIG_FILE, "example-config");
  for (const key of [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_PROFILE",
    "AWS_ENDPOINT_URL",
    "GH_TOKEN",
    "NODE_OPTIONS",
  ])
    assert.equal(clean[key], undefined);
});
