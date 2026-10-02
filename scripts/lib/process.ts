import { spawn } from "node:child_process";

export interface RunOptions {
  env?: NodeJS.ProcessEnv;
  cwd?: string;
  input?: string;
  interactive?: boolean;
  timeout?: number;
}
export interface Result {
  stdout: string;
  stderr: string;
  code: number;
}
export type Runner = (command: string, args: string[], options?: RunOptions) => Promise<Result>;

// No shell, no command interpolation, no automatic printing of subprocess output.
export const run: Runner = (command, args, options = {}) =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      shell: false,
      windowsHide: true,
      stdio: options.interactive ? "inherit" : ["pipe", "pipe", "pipe"],
    });
    let stdout = "",
      stderr = "",
      size = 0;
    let failure: Error | undefined;
    const timer = setTimeout(() => {
      failure = new Error(`${command} timed out.`);
      child.kill();
    }, options.timeout ?? 120_000);
    for (const [stream, kind] of [
      [child.stdout, "out"],
      [child.stderr, "err"],
    ] as const) {
      stream?.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > 16 * 1024 * 1024) {
          failure = new Error(`${command} exceeded the output limit.`);
          child.kill();
          return;
        }
        if (kind === "out") stdout += chunk.toString();
        else stderr += chunk.toString();
      });
    }
    child.on("error", () => {
      clearTimeout(timer);
      reject(new Error(`Cannot start ${command}; check installation and PATH.`));
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (failure) reject(failure);
      else resolve({ stdout, stderr, code: code ?? 1 });
    });
    child.stdin?.on("error", () => {}); // A failed child may close stdin early.
    child.stdin?.end(options.input);
  });

export function successful(result: Result, operation: string): string {
  if (result.code !== 0)
    throw new Error(
      `${operation} failed (exit ${result.code}). Subprocess output withheld to avoid disclosing credentials.`,
    );
  return result.stdout.trim();
}

export function json<T>(result: Result, operation: string): T {
  const output = successful(result, operation);
  try {
    return JSON.parse(output) as T;
  } catch {
    throw new Error(`${operation} returned invalid JSON.`);
  }
}

const hostKeys = new Set([
  "PATH",
  "PATHEXT",
  "SYSTEMROOT",
  "WINDIR",
  "COMSPEC",
  "HOME",
  "USERPROFILE",
  "HOMEDRIVE",
  "HOMEPATH",
  "APPDATA",
  "LOCALAPPDATA",
  "PROGRAMDATA",
  "TEMP",
  "TMP",
  "TMPDIR",
  "LANG",
  "LC_ALL",
  "TERM",
  "COLORTERM",
  "USER",
  "USERNAME",
  "XDG_CONFIG_HOME",
  "XDG_DATA_HOME",
  "XDG_STATE_HOME",
  "XDG_RUNTIME_DIR",
]);

export function hostEnvironment(env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  return Object.fromEntries(Object.entries(env).filter(([key]) => hostKeys.has(key.toUpperCase())));
}

export const nullDevice = process.platform === "win32" ? "NUL" : "/dev/null";

export function awsEnvironment(env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const clean = hostEnvironment(env);
  // Preserve only host credential-file locations and TLS settings. Ambient keys,
  // endpoint overrides, web identity, container credentials and profile selectors
  // cannot override the explicitly chosen profile.
  for (const key of [
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_LOGIN_CACHE_DIRECTORY",
    "AWS_CA_BUNDLE",
  ]) {
    if (env[key]) clean[key] = env[key];
  }
  return {
    ...clean,
    AWS_PAGER: "",
    AWS_CLI_AUTO_PROMPT: "off",
    AWS_EC2_METADATA_DISABLED: "true",
    AWS_IGNORE_CONFIGURED_ENDPOINT_URLS: "true",
  };
}
