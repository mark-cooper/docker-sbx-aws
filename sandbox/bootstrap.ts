// Runs inside the Linux microVM with Node 24. Never prints credential values.

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const sessionDir = join(homedir(), ".readonly-session");
// The reviewed sbx version (config/runtime.json) sets this fixed placeholder
// GH_TOKEN in every sandbox. It is not a host credential; the host check
// rejects any stored github secret the sbx proxy could substitute for it. Any
// other value is still refused. Recheck it when bumping sbx.
const sbxGitHubPlaceholder = "4f4a70aae7238131b9775a37bb8e16b268905073c33bdcfef7553398ba869c52";
const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");
// Launcher-made commits use a fixed identity and ignore user/system Git config.
const exportGit = {
  GIT_AUTHOR_NAME: "Sandbox export",
  GIT_AUTHOR_EMAIL: "sandbox@example.invalid",
  GIT_COMMITTER_NAME: "Sandbox export",
  GIT_COMMITTER_EMAIL: "sandbox@example.invalid",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
};
const nullProvider = {
  AWS_CONFIG_FILE: "/dev/null",
  AWS_SHARED_CREDENTIALS_FILE: "/dev/null",
  AWS_EC2_METADATA_DISABLED: "true",
  AWS_IGNORE_CONFIGURED_ENDPOINT_URLS: "true",
  AWS_CA_BUNDLE: "/etc/ssl/certs/ca-certificates.crt",
  AWS_PAGER: "",
  AWS_CLI_AUTO_PROMPT: "off",
};

function execute(
  command: string,
  args: string[],
  env: NodeJS.ProcessEnv = process.env,
  input?: string,
): string {
  const result = spawnSync(command, args, {
    env,
    input,
    encoding: "utf8",
    timeout: 120_000,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status !== 0) throw new Error(`Sandbox ${command} operation failed.`);
  return result.stdout.trim();
}
function quote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}
function cleanAwsEnv(): NodeJS.ProcessEnv {
  return Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("AWS_")));
}
function snapshot(): { tree: string; head: string; refs: string; fingerprint: string } {
  mkdirSync(sessionDir, { recursive: true, mode: 0o700 });
  const index = join(sessionDir, "collection.index");
  if (existsSync(index)) unlinkSync(index);
  const env = {
    ...process.env,
    GIT_INDEX_FILE: index,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
  };
  try {
    const head = execute("git", ["rev-parse", "HEAD"], env);
    execute("git", ["read-tree", "HEAD"], env);
    execute("git", ["-c", "core.hooksPath=/dev/null", "add", "-A", "--", "."], env);
    const tree = execute("git", ["write-tree"], env);
    const refs = execute(
      "git",
      ["for-each-ref", "--format=%(refname) %(objectname)", "refs/heads", "refs/tags"],
      env,
    );
    return {
      tree,
      head,
      refs,
      fingerprint: sha256(`${head}\n${tree}\n${refs}`),
    };
  } finally {
    if (existsSync(index)) unlinkSync(index);
  }
}

try {
  const [command] = process.argv.slice(2);
  if (command === "check") {
    if (Number(process.versions.node.split(".")[0]) < 24)
      throw new Error("Node 24 is required inside the template.");
    for (const tool of ["aws", "git", "jq", "mise"]) execute(tool, ["--version"]);
    // A Docker socket inside this VM is not the host socket. Host mounts are
    // independently checked via sbx inspect before credential injection.
    // sbx sets SSH_AUTH_SOCK even with forwarding disabled; only a socket that
    // actually exists could expose a host SSH agent.
    const agentSockets = [process.env.SSH_AUTH_SOCK, "/run/ssh-agent.sock"];
    if (agentSockets.some((socket) => socket && existsSync(socket)))
      throw new Error("Host SSH agent socket is present in fresh sandbox.");
    if (
      existsSync(join(homedir(), ".aws", "credentials")) ||
      existsSync(join(homedir(), ".aws", "config"))
    )
      throw new Error("Unexpected AWS files in fresh sandbox.");
    for (const key of [
      "AWS_ACCESS_KEY_ID",
      "AWS_SECRET_ACCESS_KEY",
      "AWS_SESSION_TOKEN",
      "AWS_PROFILE",
      "GH_TOKEN",
      "GITHUB_TOKEN",
    ]) {
      const value = process.env[key];
      if (value && !(key === "GH_TOKEN" && sha256(value) === sbxGitHubPlaceholder))
        throw new Error("Unexpected inherited credential/provider environment.");
    }
    console.log(JSON.stringify({ cwd: process.cwd(), home: homedir() }));
  } else if (command === "clone") {
    execute("git", ["init", "--initial-branch=sandbox", "."]);
    execute("git", [
      "-c",
      "core.hooksPath=/dev/null",
      "fetch",
      "/home/agent/readonly-input.bundle",
      "HEAD",
    ]);
    execute("git", ["-c", "core.hooksPath=/dev/null", "checkout", "-B", "sandbox", "FETCH_HEAD"]);
    unlinkSync("/home/agent/readonly-input.bundle");
    console.log(JSON.stringify(snapshot()));
  } else if (command === "init") {
    // No host project: an empty base commit lets snapshot, collect and destroy
    // track agent-created files exactly as in clone mode.
    const env = { ...process.env, ...exportGit };
    execute("git", ["init", "--initial-branch=sandbox", "."], env);
    execute(
      "git",
      [
        "-c",
        "core.hooksPath=/dev/null",
        "commit",
        "--allow-empty",
        "-m",
        "Empty sandbox workspace",
      ],
      env,
    );
    console.log(JSON.stringify(snapshot()));
  } else if (command === "inject") {
    const input = readFileSync(0, "utf8");
    if (input.length > 64 * 1024) throw new Error("Credential payload too large.");
    const data = JSON.parse(input);
    const c = data.credentials;
    if (
      !c ||
      !["AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"].every(
        (k) => typeof c[k] === "string" && c[k].length > 0,
      )
    )
      throw new Error("Invalid credential payload.");
    if (
      Date.parse(c.Expiration) - Date.now() < 300_000 ||
      !Number.isFinite(Date.parse(c.Expiration))
    )
      throw new Error("Insufficient credential lifetime.");
    const awsEnv = {
      ...nullProvider,
      AWS_ACCESS_KEY_ID: c.AccessKeyId,
      AWS_SECRET_ACCESS_KEY: c.SecretAccessKey,
      AWS_SESSION_TOKEN: c.SessionToken,
      AWS_CREDENTIAL_EXPIRATION: c.Expiration,
      AWS_REGION: data.region,
      AWS_DEFAULT_REGION: data.region,
    };
    const actual = JSON.parse(
      execute("aws", ["sts", "get-caller-identity", "--output", "json"], {
        ...cleanAwsEnv(),
        ...awsEnv,
      }),
    );
    if (!data.identity || ["Account", "Arn", "UserId"].some((k) => actual[k] !== data.identity[k]))
      throw new Error("Sandbox identity does not match issued credentials.");
    mkdirSync(sessionDir, { recursive: true, mode: 0o700 });
    const envFile = join(sessionDir, "aws.sh");
    if (existsSync(envFile) && lstatSync(envFile).isSymbolicLink())
      throw new Error("Invalid session credential path.");
    writeFileSync(
      envFile,
      "unset SSH_AUTH_SOCK GH_TOKEN GITHUB_TOKEN AWS_PROFILE AWS_DEFAULT_PROFILE AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN AWS_CONTAINER_CREDENTIALS_RELATIVE_URI AWS_CONTAINER_CREDENTIALS_FULL_URI\n" +
        Object.entries(awsEnv)
          .map(([k, v]) => `export ${k}=${quote(String(v))}`)
          .join("\n") +
        "\n",
      { mode: 0o600 },
    );
    chmodSync(envFile, 0o600);
    // Only the non-secret source statement goes through sudo's command path.
    // A renewal rewrites aws.sh above; the source line is added only once.
    const persistent = "/etc/sandbox-persistent.sh";
    const source = `. ${quote(envFile)}`;
    if (spawnSync("sudo", ["grep", "-qxF", source, persistent]).status !== 0)
      execute("sudo", ["tee", "-a", persistent], process.env, `\n${source}\n`);
    console.log(JSON.stringify({ identity: actual, expiration: c.Expiration }));
  } else if (command === "snapshot") {
    console.log(JSON.stringify(snapshot()));
  } else if (command === "collect") {
    const state = snapshot();
    const env = { ...process.env, ...exportGit };
    const commit = execute(
      "git",
      ["commit-tree", state.tree, "-p", state.head],
      env,
      "Sandbox work snapshot\n",
    );
    const ref = "refs/readonly-export/snapshot";
    execute("git", ["update-ref", ref, commit], env);
    try {
      execute(
        "git",
        ["bundle", "create", "/tmp/readonly-output.bundle", ref, "--branches", "--tags"],
        env,
      );
    } finally {
      execute("git", ["update-ref", "-d", ref], env);
    }
    console.log(JSON.stringify({ ...state, commit }));
  } else if (command === "probe-network") {
    // Require a real proxy denial, not an arbitrary DNS or connectivity failure.
    const proxy = process.env.HTTPS_PROXY ?? process.env.https_proxy;
    if (!proxy) throw new Error("Sandbox HTTPS proxy is missing.");
    const response = spawnSync(
      "curl",
      [
        "--silent",
        "--show-error",
        "--max-time",
        "15",
        "--proxy",
        proxy,
        "--noproxy",
        "",
        "--output",
        "/dev/null",
        "--write-out",
        "%{http_connect}:%{http_code}",
        "https://example.com/",
      ],
      { encoding: "utf8", timeout: 20_000 },
    );
    // sbx may deny CONNECT itself, or terminate TLS and return HTTP 403.
    if (!["403:000", "200:403"].includes(response.stdout.trim()))
      throw new Error("Unapproved network destination did not receive an explicit proxy denial.");
    console.log("blocked");
  } else throw new Error("Unknown sandbox bootstrap command.");
} catch (error) {
  // Error messages we create contain no credential data; JSON/parser errors can.
  console.error(
    error instanceof SyntaxError
      ? "Invalid bootstrap JSON."
      : error instanceof Error
        ? error.message
        : "Bootstrap failed.",
  );
  process.exitCode = 1;
}
