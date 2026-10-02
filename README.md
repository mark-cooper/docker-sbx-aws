# Read-only AWS agent sandboxes

Launch a coding agent in a local Docker Sandbox with a temporary session for an existing restricted AWS role. Keep your normal host AWS profiles and browser-login flow.

```sh
aws login --profile browser-login
mise run sbx run <agent> --profile profile
mise run sbx run <agent> /path/to/project --profile profile # mounts the local directory for host edits

# reattaching
mise run sbx run --name <name>
```

`<agent>` is any agent with a template in [config/runtime.json](config/runtime.json).

`mise run sbx` mirrors the [sbx CLI](https://docs.docker.com/ai/sandboxes/usage/): the same command works with or without mise. Through mise, `run` and `rm` also handle the AWS session for sandboxes this launcher manages, and any other command, such as `mise run sbx ls`, goes to sbx unchanged. Commands with no sbx equivalent are the other mise tasks (`preview`, `doctor`, `build`, `build_all`). Run `node scripts/sandbox.ts --help` for the full list.

All profile names and account IDs in this repository are fictional examples. Any profile satisfying the requirements below can be used.

## How it works

The account profile supplies `role_arn`, `source_profile`, and region as metadata. The launcher extracts the account and partition, substitutes `ReadOnlyRole` (configurable), and calls STS using the immediate source profile. It never activates the account profile's original role to discover the account or as a fallback.

```text
browser login -> source profile -> target account's ReadOnlyRole -> sandbox
                    |
                    +-> original account role (normal host workflow)
```

Only the resulting access key, secret, session token, expiry, and region enter the sandbox. They travel through stdin and live in an owner-readable file inside the microVM, outside the project. Source credentials, host AWS files, SSH agent variables, and unrelated host tokens are not forwarded.

## Requirements

- Node 24 (native `.ts` execution) and mise. There are no runtime npm dependencies.
- AWS CLI v2.32 or later and an existing `aws login` flow.
- Docker with Linux image builds, plus local Docker Sandboxes (sbx) at `minSbxVersion` in [config/runtime.json](config/runtime.json) or later. Install sbx normally and keep it updated (`brew install docker/tap/sbx`, `winget install Docker.sbx`, or `docker-sbx` from Docker's apt repository); restart the sbx daemon after upgrading. Newer releases are assumed compatible. If one breaks the launcher, report it: the fix raises the minimum. An older sbx fails with the upgrade command for your OS. sbx is not installed by mise because Windows releases ship only as MSI installers.
- An account profile with a valid IAM `role_arn`, a `source_profile` (or `--source-profile` override), and a region (or `--region`). Config and credentials files are merged using credentials-file precedence.
- A source using a login session, a trusted `credential_process`, or an intermediate role using `source_profile`. Intermediate roles are preserved. Static credentials in this chain are rejected. Arbitrary credential processes are trusted host code; preview never executes them.
- An existing restricted role, default `ReadOnlyRole`, or a name/path passed with `--role`. Its effective permissions must allow intended reads and deny writes, role escalation, and unwanted data reads such as S3 object downloads. AWS's generic read-only managed policy may allow more data access than you intend.
- Direct access from the source identity to the restricted role: target trust and, for cross-account access, source permission to assume it. Access to the original account role does not imply this permission.
- This version does not infer target accounts without `role_arn`, configure replacement-role MFA/external-ID/source-identity arguments, or refresh sandbox credentials. Roles requiring additional STS parameters fail until support is added. Sessions request one hour; role chaining cannot exceed one hour. Relaunch after expiry.

## Setup

Install the prerequisites and configure Docker Sandboxes/model authentication through Docker's host-side flows. Do not mount agent home directories into the sandbox.

```sh
mise install
npm ci --ignore-scripts  # development/typechecking only
mise run build_all  # or one agent: mise run build <agent>
```

Each template is two layers, both pinned to immutable image digests. [sandbox/Dockerfile](sandbox/Dockerfile) builds a shared base with Node, AWS CLI, mise, and the sandbox bootstrap. Each `sandbox/Dockerfile.<agent>` starts from Docker's upstream template for that agent and copies the shared base on top. The result loads into the separate sandbox image store. Downloads and loading can take several minutes. AWS CLI, Node, Git, jq, and mise are checked during preparation. Template builds use no AWS credentials.

Dependabot watches the Dockerfiles in `sandbox/` and opens a PR when a newer upstream image is available, updating the tag and digest together. CI builds the base and every agent Dockerfile on each pull request, so a Dependabot PR is mergeable only when the images still build. After merging an upgrade, run `mise run build_all` and `npm run test:runtime` to load and test the new templates in real sandboxes. Running sessions are not affected.

### Adding an agent

1. Add `sandbox/Dockerfile.<agent>` starting `FROM` Docker's sandbox template for that agent, pinned by digest, followed by the same lines as the existing agent Dockerfiles.
2. Add its template tag to [config/runtime.json](config/runtime.json) and its model/auth hosts to [config/network-policy.json](config/network-policy.json).
3. Add the agent name to `agents` in [scripts/lib/state.ts](scripts/lib/state.ts) and add its model secret name, if any, to `modelSecrets` in [scripts/lib/sandbox.ts](scripts/lib/sandbox.ts).

### AWS profiles

[examples/aws-config](examples/aws-config) shows a synthetic login/process/role chain. Create the browser-login profile with `aws login --profile browser-login`; do not copy its example login ARN verbatim. Keep an existing compatible profile layout. Settings may be split between `~/.aws/config` and `~/.aws/credentials`; the latter uses `[name]` instead of `[profile name]` sections.

For this example, the source is `session-bridge` and the replacement role is `arn:aws:iam::222222222222:role/ReadOnlyRole`. No additional read-only profile is needed.

```sh
mise run preview <agent> --profile profile
mise run doctor --profile profile --agent <agent>
mise run sbx run <agent> --profile profile
mise run sbx run <agent> /path/to/repository --profile profile
mise run sbx run <agent> /path/to/repository --profile profile --role agents/RestrictedReadOnlyRole
```

`--source-profile other-source` overrides the immediate source. AWS CLI resolves that source normally. Expired-login diagnostics identify upstream login profiles for direct login and recognized export-credentials bridges; opaque credential processes get a generic renewal hint. `doctor --agent <agent>` checks that agent's network allowlist.

### Sandbox network policy

Use a **dedicated sbx setup with default-deny network policy**, no registered MCP servers, no stored sbx secrets other than the agents' model secrets (`modelSecrets` in [scripts/lib/sandbox.ts](scripts/lib/sandbox.ts); check with `sbx secret ls`), and SSH agent forwarding disabled. sbx injects stored service secrets such as `github` into every sandbox, so remove them from the dedicated setup (for example, `sbx secret rm github`). The launcher checks settings without changing global configuration. A fresh dedicated installation can be configured with:

```sh
sbx policy init deny-all
sbx settings set ssh.agentForwardingEnabled false
sbx daemon restart
```

This sets global policy, not a per-project setting. On an existing installation, inspect `sbx policy ls --type network --wide` and establish a compatible setup using Docker's policy controls. Do not blindly reset policies used by other sandboxes.

The launcher adds sandbox-scoped TCP/443 allowances from [config/network-policy.json](config/network-policy.json):

- **Model/auth hosts** (`agents`), per agent. Deliberately small; review and add exact domains when a model/auth flow requires them.
- **Other hosts** (`hosts`, every agent): AWS documentation (`docs.aws.amazon.com`).
- **AWS domains** (`awsDomains`, per partition): `**.amazonaws.com` and `**.api.aws` (`**.amazonaws.com.cn` in China). This covers every AWS service API in every region and the global endpoints, including S3, CloudWatch Logs, Route 53, ACM, Organizations, Cost Explorer and the pricing API.

Built-in kits also grant exact download/package endpoints; the launcher adds matching per-sandbox denies for those outside the list. Only the configured wildcards are accepted: any other inherited wildcard allow (such as `**`) is rejected. After applying rules, the launcher reads the sandbox policy back, then checks a probe host beneath each wildcard, each exact host, lookalike domains (`amazonaws.com.example.com`), private and metadata addresses, and an actual in-VM proxy denial before handing over credentials. There is no skip-policy fallback. Host-wide policy/SSH changes above affect other sessions, so use a dedicated setup.

**`**.amazonaws.com` is a deliberate trade-off.** Besides AWS APIs, it admits hosts any AWS customer controls: EC2 public DNS names, load balancers, API Gateway, S3 buckets and RDS/OpenSearch endpoints. An agent could therefore send data it reads to a server someone else runs on AWS. The restricted, read-only, short-lived role is the main control; the network allowlist no longer contains exfiltration within AWS. Remove `awsDomains` wildcards in favor of exact hosts if that matters for your use. Organizations data is only readable from the management or a delegated administrator account. Package registries, Git hosts and LAN destinations are not enabled. Install needed project dependencies in a reviewed template.

Resume applies the current list to an existing sandbox before checking it, so allowlist changes take effect on the next resume.

## Workspace and lifecycle

**Empty mode is the default.** Without a path, the agent starts in an empty workspace and no host files are transferred. This suits AWS investigation that needs no source code. Files created there remain available while the sandbox exists, including after resume, but are lost when it is destroyed. The launcher warns about this at launch. The current directory is never used implicitly. A relative path is resolved from the directory you ran mise in.

**Project mode** is selected by passing a path after the agent and mounts that local directory for host edits. The agent can read and change files there immediately, including uncommitted and ignored files. Do not choose a directory containing credentials or private keys. Host home and its ancestors are rejected as project roots.

Each launch prints its unique name and credential expiry. The sandbox is retained after the agent exits:

```sh
mise run sbx run --name <name>  # reattach
mise run sbx rm <name>
```

Resume reattaches to a ready session. It first repeats the host checks (sbx version and settings, stored secrets, global and sandbox network policy). If less than 15 minutes of the one-hour AWS session remain, it assumes the restricted role again on the host and hands the new session to the sandbox the same way launch does; new shells then use it. This needs a valid upstream `aws login`. Renewal happens only on resume, not while an agent is running. Reattach with `mise run sbx run --name <name>` from anywhere; `--name` is recognized regardless of where it appears, so `mise run sbx run <agent> --name <name>` also reattaches, with `<agent>` only confirming it matches the sandbox (a mismatch is rejected). The same command without mise skips the checks and never renews credentials. A `--name` not recognized as one of this launcher's sandboxes is passed straight through to `sbx`, unchecked.

Destroy stops the active agent session and removes the sandbox. Mounted project files remain on the host. Files created only in an empty sandbox are lost. Failed launches are stopped and retained for inspection. Only recorded launcher sessions can be destroyed through these tasks.

Non-secret metadata lives under `~/.readonly-agent-sandbox`; use `READONLY_SANDBOX_STATE_DIR` to choose another location. Credentials are never written to host state. Sessions created by the previous clone/collect launcher must be collected or destroyed with that version before upgrading, so their work is not silently discarded.

## Development

```sh
npm ci --ignore-scripts
npm run check
node scripts/sandbox.ts --help
```

Tests use synthetic profiles and credentials without model calls or AWS access. CI runs host checks on Windows, macOS, and Linux. Subprocesses use argument arrays without a shell. Host scripts and the Linux sandbox bootstrap are TypeScript.

Before production use, validate a real session in a controlled AWS account: permitted reads succeed, writes/further role assumption/prohibited reads fail, credentials expire, and mounted project edits appear on the host. Identity checks do not prove IAM policy correctness. Allowed model endpoints can receive any data the role can read.

## References

- [AWS login and process bridge](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sign-in.html)
- [AWS role profiles](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html)
- [AWS AssumeRole](https://docs.aws.amazon.com/cli/latest/reference/sts/assume-role.html)
- [Docker sandbox usage](https://docs.docker.com/ai/sandboxes/usage/)
- [Docker local network policy](https://docs.docker.com/ai/sandboxes/governance/access-controls/local/)
