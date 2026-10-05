import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { run as execute, hostEnvironment } from "./lib/process.ts";
import { readProfiles, selectTarget } from "./lib/profiles.ts";
import { buildTemplate, configuration, destroy, doctor, launch, resume } from "./lib/sandbox.ts";
import { agents, validateName } from "./lib/state.ts";

const help = `Usage:
  mise run sbx run <agent> [PATH] [--profile NAME] [aws options]
      Launch an agent from this launcher's template, with a restricted AWS session when
      --profile is given; PATH is mounted for host edits (default: disposable empty
      workspace).
  mise run sbx run --name <sandbox> [<agent>]
      Reattach to a managed sandbox from anywhere, renewing its AWS session when under
      15 minutes remain. <agent> is optional and only confirms it matches the sandbox.
  mise run sbx rm <sandbox>
      Stop and remove a managed sandbox.
  mise run sbx <any other sbx command>
      Passed to sbx unchanged (ls, stop, ...).

  mise run preview <agent> [PATH] [--profile NAME] [aws options]
  mise run doctor [--profile NAME] [aws options]
  mise run build <agent>
  mise run build_all

AWS options:
  --profile NAME          Account profile supplying role_arn, source_profile and region;
                          without it the sandbox gets no AWS session or AWS domains
  --source-profile NAME   Override the account profile's immediate source_profile
  --role NAME_OR_PATH     Restricted role to assume (default ReadOnlyRole)
  --region REGION         Override the account profile's region

This project's hosts are added to your existing sbx network policy (balanced is
recommended); SSH agent forwarding, stored secrets and MCP servers are reported.

With Node directly: node scripts/sandbox.ts <sbx|preview|doctor|build> ...
Preview reads local profile metadata only; it does not run credential processes.
`;

const awsOptions = {
  profile: { type: "string" },
  "source-profile": { type: "string" },
  role: { type: "string" },
  region: { type: "string" },
} as const;

function managed(name: string | undefined): name is string {
  if (!name) return false;
  try {
    validateName(name);
    return true;
  } catch {
    return false;
  }
}

// No profile means no AWS session; the other AWS options then have nothing to modify.
async function target(values: {
  profile?: string;
  "source-profile"?: string;
  role?: string;
  region?: string;
}) {
  if (!values.profile) {
    if (values["source-profile"] || values.role || values.region)
      throw new Error(`--source-profile, --role and --region require --profile.\n${help}`);
    return undefined;
  }
  return selectTarget(await readProfiles(), values.profile, {
    sourceProfile: values["source-profile"],
    role: values.role,
    region: values.region,
  });
}

// <agent> [PATH] [--profile NAME], shared by sbx run and preview.
async function launchArgs(args: string[]) {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    strict: true,
    options: awsOptions,
  });
  const [agent, project, ...extra] = positionals;
  if (!agent || extra.length) throw new Error(`Expected <agent> and at most one PATH.\n${help}`);
  if (!agents.includes(agent))
    throw new Error(`Unsupported agent. Supported: ${agents.join(", ")}.`);
  // mise runs tasks from the launcher root; resolve PATH like sbx would, from the caller's directory.
  const base = process.env.MISE_ORIGINAL_CWD ?? process.cwd();
  return {
    agent,
    project: project && resolve(base, project),
    target: await target(values),
  };
}

async function passThrough(args: string[]): Promise<void> {
  const result = await execute("sbx", args, {
    env: hostEnvironment(),
    interactive: true,
    timeout: 24 * 60 * 60 * 1000,
  });
  process.exitCode = result.code;
}

async function sbx(args: string[]): Promise<void> {
  const [command, ...rest] = args;
  if (!command) {
    console.log(help);
    return;
  }
  if (command === "run") {
    // --name can appear anywhere (before or after an optional confirming agent),
    // matching how sbx itself accepts it.
    const nameIndex = rest.findIndex((arg) => arg === "--name" || arg.startsWith("--name="));
    if (nameIndex !== -1) {
      const flag = rest[nameIndex];
      const name = flag === "--name" ? rest[nameIndex + 1] : flag.slice("--name=".length);
      const consumed = flag === "--name" ? 2 : 1;
      const positionals = [...rest.slice(0, nameIndex), ...rest.slice(nameIndex + consumed)];
      if (managed(name)) {
        if (
          positionals.length > 1 ||
          (positionals.length === 1 && !agents.includes(positionals[0]))
        )
          throw new Error(
            `Reattach takes only --name <sandbox>, with an optional agent to confirm it.\n${help}`,
          );
        return resume(name, execute, positionals[0]);
      }
      // Not a sandbox this launcher manages: let sbx handle it directly (no host
      // checks or AWS session renewal).
    } else {
      const hasProfile = rest.some((arg) => arg === "--profile" || arg.startsWith("--profile="));
      if (hasProfile || agents.includes(rest[0] ?? "")) {
        const { agent, project, target } = await launchArgs(rest);
        await launch(target, { agent, project });
        return;
      }
    }
  }
  if (command === "rm" && rest.some(managed)) {
    const names = rest.filter((arg) => arg !== "--force" && arg !== "-f");
    if (names.length !== 1 || !managed(names[0]))
      throw new Error("Remove one managed sandbox at a time.");
    return destroy(names[0]);
  }
  return passThrough(args);
}

export async function main(args: string[]): Promise<void> {
  const [command, ...rest] = args;
  if (command === "sbx") return sbx(rest);
  if (!command || command === "--help" || rest.includes("--help")) {
    console.log(help);
    return;
  }
  if (command === "preview") {
    const { agent, project, target } = await launchArgs(rest);
    console.log(
      JSON.stringify(
        {
          agent,
          ...(target ?? { profile: null }),
          workspaceMode: project ? "mounted" : "empty",
          project: project ?? null,
        },
        null,
        2,
      ),
    );
    return;
  }
  if (command === "doctor") {
    const { values, positionals } = parseArgs({
      args: rest,
      allowPositionals: true,
      strict: true,
      options: awsOptions,
    });
    if (positionals.length) throw new Error(`doctor takes only options.\n${help}`);
    await doctor(await target(values));
    return;
  }
  if (command === "build") {
    if (rest.length === 1 && rest[0] === "--all") {
      for (const agent of Object.keys((await configuration()).runtime.templates))
        await buildTemplate(agent);
      return;
    }
    if (rest.length !== 1 || rest[0].startsWith("-"))
      throw new Error(`Expected one agent or --all.\n${help}`);
    await buildTemplate(rest[0]);
    return;
  }
  throw new Error(`Unknown command.\n${help}`);
}

if (import.meta.main)
  main(process.argv.slice(2)).catch((error) => {
    console.error(error instanceof Error ? error.message : "Command failed.");
    process.exitCode = 1;
  });
