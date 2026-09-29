import { randomUUID } from "node:crypto";
import type { Runner } from "./process.ts";
import { awsEnvironment, hostEnvironment, json, nullDevice } from "./process.ts";
import type { Target } from "./profiles.ts";

const credentialFields = ["AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"] as const;
const cliOutput = ["--output", "json", "--no-cli-pager"];

export interface Identity {
  Account: string;
  Arn: string;
  UserId: string;
}
export interface Session {
  credentials: {
    AccessKeyId: string;
    SecretAccessKey: string;
    SessionToken: string;
    Expiration: string;
  };
  identity: Identity;
  sourceArn: string;
}

export function validateIdentity(actual: Identity, expected: Identity): void {
  if (
    !actual ||
    actual.Account !== expected.Account ||
    actual.Arn !== expected.Arn ||
    actual.UserId !== expected.UserId
  )
    throw new Error("Restricted credential identity mismatch; refusing to start agent.");
}

export function validateLifetime(expiration: string, now = Date.now()): void {
  const remaining = Date.parse(expiration) - now;
  if (!Number.isFinite(remaining) || remaining < 300_000)
    throw new Error(
      "Credentials have less than five minutes remaining. Relaunch after renewing the upstream login.",
    );
}

export async function assumeRestrictedRole(
  target: Target,
  run: Runner,
  env = process.env,
): Promise<Session> {
  const hostEnv = awsEnvironment(env);
  const flags = ["--profile", target.sourceProfile, "--region", target.region, ...cliOutput];
  const hint = target.loginProfile
    ? `Run aws login --profile ${JSON.stringify(target.loginProfile)}.`
    : `Renew the upstream login for source profile ${JSON.stringify(target.sourceProfile)}.`;
  const source = json<Identity>(
    await run("aws", ["sts", "get-caller-identity", ...flags], { env: hostEnv }),
    `Source authentication. ${hint}`,
  );
  if (!source.Arn || !source.Account || !source.UserId)
    throw new Error("Invalid source identity response.");
  const sessionName = `agent-${randomUUID()}`;
  const result = json<{
    Credentials: Session["credentials"];
    AssumedRoleUser: { Arn: string; AssumedRoleId: string };
  }>(
    await run(
      "aws",
      [
        "sts",
        "assume-role",
        ...flags,
        "--role-arn",
        target.roleArn,
        "--role-session-name",
        sessionName,
        "--duration-seconds",
        "3600",
      ],
      { env: hostEnv },
    ),
    `Direct restricted-role assumption. Check source permissions and target trust. ${hint}`,
  );
  const credentials = result.Credentials;
  if (
    !credentials ||
    !credentialFields.every(
      (key) => typeof credentials[key] === "string" && credentials[key].length > 0,
    )
  )
    throw new Error("Incomplete temporary credentials from STS.");
  validateLifetime(credentials.Expiration);
  const expectedArn = `arn:${target.partition}:sts::${target.account}:assumed-role/${target.role.split("/").at(-1)}/${sessionName}`;
  if (
    result.AssumedRoleUser?.Arn !== expectedArn ||
    !result.AssumedRoleUser.AssumedRoleId?.endsWith(`:${sessionName}`)
  )
    throw new Error("AssumeRole returned an unexpected role identity.");
  const identity = {
    Account: target.account,
    Arn: result.AssumedRoleUser.Arn,
    UserId: result.AssumedRoleUser.AssumedRoleId,
  };
  // Empty provider files ensure verification cannot fall back to host credentials.
  const restrictedEnv = {
    ...hostEnvironment(env),
    ...credentialEnvironment(credentials, target.region),
    AWS_CA_BUNDLE: env.AWS_CA_BUNDLE,
  };
  const actual = json<Identity>(
    await run("aws", ["sts", "get-caller-identity", "--region", target.region, ...cliOutput], {
      env: restrictedEnv,
    }),
    "Restricted identity verification",
  );
  validateIdentity(actual, identity);
  return { credentials, identity, sourceArn: source.Arn };
}

export function credentialEnvironment(
  credentials: Session["credentials"],
  region: string,
): NodeJS.ProcessEnv {
  return {
    AWS_ACCESS_KEY_ID: credentials.AccessKeyId,
    AWS_SECRET_ACCESS_KEY: credentials.SecretAccessKey,
    AWS_SESSION_TOKEN: credentials.SessionToken,
    AWS_CREDENTIAL_EXPIRATION: credentials.Expiration,
    AWS_REGION: region,
    AWS_DEFAULT_REGION: region,
    AWS_EC2_METADATA_DISABLED: "true",
    AWS_IGNORE_CONFIGURED_ENDPOINT_URLS: "true",
    AWS_PAGER: "",
    AWS_CLI_AUTO_PROMPT: "off",
    AWS_CONFIG_FILE: nullDevice,
    AWS_SHARED_CREDENTIALS_FILE: nullDevice,
  };
}
