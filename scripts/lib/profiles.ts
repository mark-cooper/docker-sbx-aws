import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

export type Profiles = Map<string, Record<string, string>>;
export interface Target {
  profile: string;
  sourceProfile: string;
  account: string;
  partition: string;
  region: string;
  role: string;
  roleArn: string;
  loginProfile?: string;
}
export interface Selection {
  sourceProfile?: string;
  // The caller resolves --role against config/runtime.json's defaultRole.
  role: string;
  region?: string;
}

// Read INI metadata only. Nested service/SSO blocks are ignored, never executed.
export function parseProfiles(text: string, kind: "config" | "credentials"): Profiles {
  const profiles: Profiles = new Map();
  let current: Record<string, string> | undefined;
  let nested = false;
  for (const raw of text.replace(/^\uFEFF/, "").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || /^[#;]/.test(line)) continue;
    const section = /^\[([^\]]+)\]\s*(?:[#;].*)?$/.exec(line);
    if (section) {
      let name = section[1].trim();
      if (kind === "config" && name !== "default") {
        if (!name.startsWith("profile ")) {
          current = undefined;
          continue;
        }
        name = name
          .slice(8)
          .trim()
          .replace(/^"(.*)"$/, "$1");
      }
      if (profiles.has(name)) throw new Error(`Duplicate ${kind} profile section.`);
      current = Object.create(null) as Record<string, string>;
      profiles.set(name, current);
      nested = false;
      continue;
    }
    if (!current) continue;
    if (nested && /^\s/.test(raw)) continue;
    const match = /^([A-Za-z0-9_]+)\s*=\s*(.*)$/.exec(line);
    if (!match) throw new Error(`Unsupported ${kind} profile syntax.`);
    const key = match[1].toLowerCase();
    if (key in current) throw new Error(`Duplicate ${kind} profile setting: ${key}.`);
    current[key] = match[2].trim();
    nested = current[key] === "";
  }
  return profiles;
}

export function mergeProfiles(config: Profiles, credentials: Profiles): Profiles {
  const merged: Profiles = new Map([...config].map(([name, values]) => [name, { ...values }]));
  for (const [name, values] of credentials) merged.set(name, { ...merged.get(name), ...values });
  return merged;
}

export async function readProfiles(env: NodeJS.ProcessEnv = process.env): Promise<Profiles> {
  async function read(path: string) {
    try {
      return await readFile(resolve(path), "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return "";
      throw new Error("Unable to read AWS profile files.");
    }
  }
  const [config, credentials] = await Promise.all([
    read(env.AWS_CONFIG_FILE ?? join(homedir(), ".aws", "config")),
    read(env.AWS_SHARED_CREDENTIALS_FILE ?? join(homedir(), ".aws", "credentials")),
  ]);
  return mergeProfiles(parseProfiles(config, "config"), parseProfiles(credentials, "credentials"));
}

// Recognize the standard AWS login bridge solely for validation and re-login
// guidance. Other trusted credential_process commands remain opaque to us.
export function bridgeProfile(command: string): string | undefined {
  const tokens = command
    .match(/"[^"\r\n]*"|'[^'\r\n]*'|[^\s]+/g)
    ?.map((s) => s.replace(/^(["'])(.*)\1$/, "$2"));
  if (!tokens || !/(?:^|[\\/])aws(?:\.exe)?$/i.test(tokens[0])) return;
  if (tokens[1] !== "configure" || tokens[2] !== "export-credentials") return;
  const profile = tokens.indexOf("--profile");
  const format = tokens.indexOf("--format");
  if (tokens.length !== 7 || profile < 3 || format < 3 || tokens[format + 1] !== "process") return;
  return tokens[profile + 1];
}

export function selectTarget(profiles: Profiles, profile: string, options: Selection): Target {
  const metadata = profiles.get(profile);
  if (!metadata) throw new Error(`AWS profile ${JSON.stringify(profile)} does not exist.`);
  const arn = /^arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role\/([^\s]+)$/.exec(
    metadata.role_arn ?? "",
  );
  if (!arn)
    throw new Error(
      "Selected profile must have a valid IAM role_arn; its credentials will not be activated for account discovery.",
    );
  const role = options.role;
  if (typeof role !== "string" || !role)
    throw new Error("No restricted role: pass --role or set defaultRole in config/runtime.json.");
  if (!/^(?:[A-Za-z0-9+=,.@_-]+\/)*[A-Za-z0-9+=,.@_-]{1,64}$/.test(role) || role.length > 576)
    throw new Error("Role must be an IAM role name or path, not an ARN.");
  const sourceProfile = options.sourceProfile ?? metadata.source_profile;
  if (!sourceProfile)
    throw new Error("Selected profile needs source_profile or an explicit --source-profile.");
  const seen = new Set([profile]);
  let cursor: string | undefined = sourceProfile,
    loginProfile: string | undefined;
  while (cursor) {
    if (seen.has(cursor))
      throw new Error("Source profile chain is cyclic or activates the selected account profile.");
    seen.add(cursor);
    const source = profiles.get(cursor);
    if (!source) throw new Error(`Source profile ${JSON.stringify(cursor)} does not exist.`);
    if (source.aws_access_key_id || source.aws_secret_access_key || source.aws_session_token)
      throw new Error(
        "Static credentials in the source chain are unsupported; use the documented aws login flow.",
      );
    if (source.login_session) loginProfile = cursor;
    if (source.role_arn) {
      if (!source.source_profile || source.credential_source || source.web_identity_token_file)
        throw new Error(
          "Intermediate roles must use source_profile in this initial implementation.",
        );
      cursor = source.source_profile;
    } else if (source.credential_process) cursor = bridgeProfile(source.credential_process);
    else if (source.login_session) cursor = undefined;
    else
      throw new Error(
        "Credential source must resolve through login_session, credential_process, or a source_profile role chain.",
      );
  }
  const region = options.region ?? metadata.region;
  if (!region || !/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(region))
    throw new Error("Set a valid region in the selected profile or pass --region.");
  if (
    (arn[1] === "aws-cn") !== region.startsWith("cn-") ||
    (arn[1] === "aws-us-gov") !== region.startsWith("us-gov-")
  )
    throw new Error("Region does not match the target ARN partition.");
  return {
    profile,
    sourceProfile,
    account: arn[2],
    partition: arn[1],
    region,
    role,
    roleArn: `arn:${arn[1]}:iam::${arn[2]}:role/${role}`,
    loginProfile,
  };
}
