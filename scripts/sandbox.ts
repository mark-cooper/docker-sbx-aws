import { parseArgs } from "node:util";
import { readProfiles, selectTarget } from "./lib/profiles.ts";
import { buildTemplate, destroy, doctor, launch, resume } from "./lib/sandbox.ts";
import { agents } from "./lib/state.ts";

const help = `Usage:
  mise run sandbox <claude|codex> <profile> [options]
  mise run sandbox:preview <claude|codex> <profile> [options]
  mise run sandbox:doctor <profile> [--agent claude|codex] [options]
  mise run sandbox:template <claude|codex>
  mise run sandbox:resume <sandbox>
  mise run sandbox:destroy <sandbox>

Options:
  --source-profile NAME   Override the account profile's immediate source_profile
  --role NAME_OR_PATH     Restricted role to assume (default ReadOnlyRole)
  --region REGION         Override the account profile's region
  --project DIRECTORY     Mount and edit this directory (absolute path; default: disposable empty workspace)
  --help                  Show this help

With Node directly: node scripts/sandbox.ts <launch|preview|doctor|template|resume|destroy> ...
Preview reads local profile metadata only; it does not run credential processes.
Resume repeats host checks and renews the AWS session when under 15 minutes remain.
`;

export async function main(args: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    strict: true,
    options: {
      "source-profile": { type: "string" },
      role: { type: "string" },
      region: { type: "string" },
      project: { type: "string" },
      agent: { type: "string" },
      help: { type: "boolean" },
    },
  });
  if (values.help || !positionals.length) {
    console.log(help);
    return;
  }
  const [command, ...params] = positionals;
  const allowedOptions: Record<string, string[]> = {
    launch: ["source-profile", "role", "region", "project"],
    preview: ["source-profile", "role", "region", "project"],
    doctor: ["source-profile", "role", "region", "agent"],
    template: [],
    resume: [],
    destroy: [],
  };
  if (!allowedOptions[command]) throw new Error(`Unknown command.\n${help}`);
  if (Object.keys(values).some((key) => !allowedOptions[command].includes(key)))
    throw new Error("An option is not supported by this command.");
  const expected = ["launch", "preview"].includes(command) ? 2 : 1;
  if (params.length !== expected) throw new Error(`Incorrect arguments.\n${help}`);
  if (command === "template") {
    await buildTemplate(params[0]);
    return;
  }
  if (command === "resume") {
    await resume(params[0]);
    return;
  }
  if (command === "destroy") {
    await destroy(params[0]);
    return;
  }
  const agent = command === "doctor" ? (values.agent ?? "claude") : params[0];
  if (!agents.includes(agent)) throw new Error("Agent must be claude or codex.");
  const profile = command === "doctor" ? params[0] : params[1];
  const target = selectTarget(await readProfiles(), profile, {
    sourceProfile: values["source-profile"],
    role: values.role,
    region: values.region,
  });
  if (command === "preview") {
    console.log(
      JSON.stringify(
        {
          agent,
          ...target,
          workspaceMode: values.project ? "mounted" : "empty",
          project: values.project ?? null,
        },
        null,
        2,
      ),
    );
    return;
  }
  if (command === "doctor") {
    await doctor(target, agent);
    return;
  }
  await launch(target, { agent, project: values.project });
}

if (import.meta.main)
  main(process.argv.slice(2)).catch((error) => {
    console.error(error instanceof Error ? error.message : "Command failed.");
    process.exitCode = 1;
  });
