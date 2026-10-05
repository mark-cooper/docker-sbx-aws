import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { run as execute, hostEnvironment } from "./lib/process.ts";
import { readProfiles, selectTarget } from "./lib/profiles.ts";
import { buildTemplate, configuration, destroy, doctor, launch, resume } from "./lib/sandbox.ts";
import { agents, defaultName, managedState } from "./lib/state.ts";

const help = `Usage:
  mise run sbx run <agent> [PATH] [--name NAME] [--profile NAME] [aws options]
      Launch an agent from this launcher's template, with a restricted AWS session when
      --profile is given; PATH is mounted for host edits (default: disposable empty
      workspace). The sandbox is named NAME, or <agent>-<PATH's directory name> (the
      current directory's name without PATH). If that managed sandbox already exists
      with the same agent, PATH and AWS options, this reattaches to it.
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

// Managed means this launcher holds live state for the sandbox, whatever its name.
async function managed(name: string | undefined): Promise<boolean> {
  return !!name && !!(await managedState(name));
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

// <agent> [PATH] [--name NAME] [--profile NAME], shared by sbx run and preview.
async function launchArgs(args: string[]) {
  const {
    values: { name, ...values },
    positionals,
  } = parseArgs({
    args,
    allowPositionals: true,
    strict: true,
    options: { ...awsOptions, name: { type: "string" } },
  });
  const [agent, project, ...extra] = positionals;
  if (!agent || extra.length) throw new Error(`Expected <agent> and at most one PATH.\n${help}`);
  if (!agents.includes(agent))
    throw new Error(`Unsupported agent. Supported: ${agents.join(", ")}.`);
  // mise runs tasks from the launcher root; resolve PATH like sbx would, from the caller's directory.
  const base = process.env.MISE_ORIGINAL_CWD ?? process.cwd();
  const path = project && resolve(base, project);
  return {
    agent,
    project: path,
    name: name ?? defaultName(agent, path ?? base),
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
    // --name can appear anywhere, matching how sbx itself accepts it.
    const nameIndex = rest.findIndex((arg) => arg === "--name" || arg.startsWith("--name="));
    const flag = rest[nameIndex];
    const name = flag === "--name" ? rest[nameIndex + 1] : flag?.slice("--name=".length);
    const others = nameIndex === -1 ? rest : rest.toSpliced(nameIndex, flag === "--name" ? 2 : 1);
    const isManaged = await managed(name);
    // --name of a managed sandbox, optionally with its agent to confirm it, reattaches.
    if (isManaged && (others.length === 0 || (others.length === 1 && agents.includes(others[0]))))
      return resume(name, execute, others[0]);
    // An agent or --profile launches through this launcher; launching an
    // existing managed sandbox again reattaches when nothing would change.
    const hasProfile = others.some((arg) => arg === "--profile" || arg.startsWith("--profile="));
    if (hasProfile || agents.includes(others[0] ?? "")) {
      const { target, ...options } = await launchArgs(rest);
      await launch(target, options);
      return;
    }
    if (isManaged)
      throw new Error(
        `Reattach takes only --name <sandbox>, with an optional agent to confirm it.\n${help}`,
      );
    // Not a sandbox this launcher manages: let sbx handle it directly (no host
    // checks or AWS session renewal).
  }
  if (command === "rm" && (await Promise.all(rest.map(managed))).some(Boolean)) {
    const names = rest.filter((arg) => arg !== "--force" && arg !== "-f");
    if (names.length !== 1 || !(await managed(names[0])))
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
    const { agent, project, name, target } = await launchArgs(rest);
    console.log(
      JSON.stringify(
        {
          agent,
          name,
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
