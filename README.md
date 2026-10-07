# Read-only AWS agent sandboxes

Launch a coding agent in a local Docker Sandbox with a temporary session for an existing restricted AWS role. Keep your normal host AWS profiles and browser-login flow.

```sh
aws login --profile browser-login
mise run sbx run <agent> --profile profile
mise run sbx run <agent> /path/to/project --profile profile # mounts the local directory for host edits
mise run sbx run <agent> /path/to/project                   # same template, no AWS session
mise run sbx run <agent> --name my-box --profile profile    # choose the sandbox name

# reattaching
mise run sbx run --name <name>
```

`<agent>` is any agent with a template in [config/runtime.json](config/runtime.json).

Without `--profile` the sandbox uses the same template and checks but gets no AWS session and no AWS domains in its network allowlist; `--source-profile`, `--role`, and `--region` then aren't accepted. Reattaching such a sandbox never contacts AWS.

`mise run sbx` mirrors the [sbx CLI](https://docs.docker.com/ai/sandboxes/usage/): the same command works with or without mise. Through mise, `run` and `rm` also handle the AWS session; any other command, like `mise run sbx ls`, goes to sbx unchanged. The other mise tasks (`preview`, `doctor`, `build`, `build_all`) have no sbx equivalent. Run `node scripts/sandbox.ts --help` for the full list.

All profile names and account IDs in this repository are fictional examples.

## How it works

The account profile supplies `role_arn`, `source_profile`, and region as metadata. The launcher extracts the account and partition, substitutes the restricted role (`defaultRole` in [config/runtime.json](config/runtime.json), default `ReadOnlyRole`, or `--role`, which takes precedence), and calls STS using the immediate source profile. It never activates the account profile's original role to discover the account or as a fallback.

```text
browser login -> source profile -> target account's ReadOnlyRole -> sandbox
                    |
                    +-> original account role (normal host workflow)
```

Only the resulting access key, secret, session token, expiry, and region enter the sandbox, via stdin, stored in an owner-readable file inside the microVM, outside the project. Source credentials, host AWS files, and unrelated host tokens are not forwarded by the launcher. Access sbx itself grants — SSH agent forwarding, stored service secrets, MCP servers — is left as you configured it and reported at launch (see [Sandbox network policy](#sandbox-network-policy)).

## Requirements

- Node 24 (native `.ts` execution) and mise. No runtime npm dependencies.
- AWS CLI v2.32+ and an existing `aws login` flow.
- Docker with Linux image builds, plus local Docker Sandboxes (sbx) at `minSbxVersion` in [config/runtime.json](config/runtime.json) or later. Install via `brew install docker/tap/sbx`, `winget install Docker.sbx`, or `docker-sbx` from Docker's apt repo, and restart the sbx daemon after upgrading. If a newer release breaks the launcher, report it to raise the minimum; an older sbx fails with an upgrade hint. sbx isn't installed by mise since Windows ships it only as an MSI.
- An account profile with a valid IAM `role_arn`, a `source_profile` (or `--source-profile` override), and a region (or `--region`).
- A source using a login session, a trusted `credential_process`, or an intermediate role via `source_profile`. Static credentials anywhere in this chain are rejected. Credential processes are trusted host code and are never executed by preview.
- An existing restricted role (`defaultRole` in [config/runtime.json](config/runtime.json), or `--role`) whose effective permissions allow intended reads and deny writes, role escalation, and unwanted data reads (e.g. S3 object downloads) — AWS's generic read-only managed policy may allow more than you intend.
- Direct access from the source identity to the restricted role: target trust and, for cross-account access, source permission to assume it. Access to the original account role does not imply this.
- Not supported yet: inferring target accounts without `role_arn`, replacement-role MFA/external-ID/source-identity arguments, or refreshing credentials mid-session. Sessions request `sessionDurationSeconds` from [config/runtime.json](config/runtime.json) (default one hour). Longer sessions need the restricted role's maximum session duration raised, and STS caps chained role sessions — an intermediate role, or a login session that is itself an assumed role — at one hour; relaunch or resume after expiry.

## Setup

Install the prerequisites and configure Docker Sandboxes/model authentication through Docker's host-side flows. Do not mount agent home directories into the sandbox.

```sh
mise install
npm ci --ignore-scripts  # development/typechecking only
mise run build_all  # or one agent: mise run build <agent>
```

Each `sandbox/Dockerfile.<agent>` is a self-contained, independently buildable multi-stage build: it starts from Docker's upstream template for that agent, pinned by digest, then layers in Node, AWS CLI, and mise from their own pinned upstream images. Every agent Dockerfile shares an identical body — only the first `FROM ... AS base` line differs — and a test (`tests/dockerfiles.test.ts`) fails CI if they ever drift apart. Builds load into the separate sandbox image store and can take several minutes; they use no AWS credentials.

Dependabot opens a PR when a newer upstream image is available, updating tag and digest together; CI builds every Dockerfile on each PR. After merging an upgrade, or after changing `sandbox/bootstrap.ts` (bump the template tags in [config/runtime.json](config/runtime.json) so stale templates aren't used), run `mise run build_all` and `npm run test:runtime` to load and test the new templates — running sessions are unaffected.

### Adding an agent

1. Add `sandbox/Dockerfile.<agent>` starting `FROM` Docker's sandbox template for that agent, pinned by digest, followed by the same lines as the existing agent Dockerfiles (`tests/dockerfiles.test.ts` will fail if it diverges).
2. Add a template to [config/runtime.json](config/runtime.json) keyed by the agent name, with its `tag` and, if sbx manages a model secret for it, `modelSecret` (the sbx service secret name, e.g. `anthropic`). The template keys are the supported agents.
3. Add its model/auth hosts to [config/network-policy.json](config/network-policy.json). `tests/config.test.ts` fails if templates, Dockerfiles and network hosts don't list the same agents.

### AWS profiles

[examples/aws-config](examples/aws-config) shows a synthetic login/process/role chain — create the browser-login profile with `aws login --profile browser-login`, but don't copy its example login ARN verbatim. Keep an existing compatible profile layout; settings may be split between `~/.aws/config` and `~/.aws/credentials` (the latter uses `[name]` instead of `[profile name]`).

In this example the source is `session-bridge` and the replacement role is `arn:aws:iam::222222222222:role/ReadOnlyRole`; no additional read-only profile is needed.

```sh
mise run preview <agent> --profile profile
mise run doctor --profile profile --agent <agent>
mise run sbx run <agent> --profile profile
mise run sbx run <agent> /path/to/repository --profile profile
mise run sbx run <agent> /path/to/repository --profile profile --role agents/RestrictedReadOnlyRole
```

`--source-profile other-source` overrides the immediate source (resolved normally by the AWS CLI). Expired-login diagnostics identify upstream login profiles and recognized export-credentials bridges; opaque credential processes get a generic renewal hint. `doctor` runs the host sbx and network policy checks, then verifies role assumption; without `--profile` it runs only the host checks.

### Sandbox network policy

The restricted, short-lived AWS role is the primary control; the network policy is a secondary layer. The launcher works with your existing sbx setup, and **the recommended sbx network policy is `balanced`**. Choose it when sbx first asks, or switch with `sbx policy init balanced`. That resets global policy, so check what other sandboxes rely on first (`sbx policy ls --type network --wide`).

The launcher:

- adds sandbox-scoped allows for this project's hosts (below) on top of your policy, without changing global policy;
- adds sandbox-scoped denies for instance metadata (`169.254.169.254`, `fd00:ec2::254/128`) and `blockedHosts`; denies override any allow, including your own policy's;
- refuses a policy that allows every destination (`**`, `0.0.0.0/0`), and checks that instance metadata stays blocked, since on a cloud host it would hand the agent the host's own credentials;
- warns, before creating the sandbox, about other access the agent gets: SSH agent forwarding, stored service secrets such as `github`, and registered MCP servers.

SSH agent forwarding gives the agent every key in your agent, typically for longer and more widely than the AWS session. Prefer a separate agent holding only the keys the agent needs, ideally added with `ssh-add -c` so each use asks for confirmation, set via `sbx settings set ssh.agentSocketPath`.

The launcher adds sandbox-scoped TCP/443 allowances from [config/network-policy.json](config/network-policy.json):

- **Model/auth hosts** (`agents`), per agent — deliberately small; add exact domains only when a flow requires them.
- **Other hosts** (`allowedHosts`, every agent): `docs.aws.amazon.com`, `docs.docker.com`, `mise.jdx.dev`.
- **AWS domains** (`awsDomains`, per partition): `**.amazonaws.com` and `**.api.aws` (`**.amazonaws.com.cn` in China) — every AWS service API in every region plus global endpoints (S3, CloudWatch Logs, Route 53, ACM, Organizations, Cost Explorer, pricing API).

It also denies `blockedHosts` (every agent, all ports), such as PyPI, Azure, VS Code and Vercel. Entries are DNS names or `*.`/`**.` wildcards. A block may carve a host out of an allowed wildcard but must not cover an allowed host. Removing a block does not remove the deny from existing sandboxes: `sbx policy rm network --sandbox <name> --resource <host>`.

After applying rules, the launcher reads the policy back and probes a host beneath each wildcard and each exact host, allowed or blocked, before handing over credentials — there is no skip-policy fallback. When your policy blocks `example.com`, it also checks from inside the sandbox that the proxy denies it.

**Egress is not a hard boundary.** `**.amazonaws.com` admits hosts any AWS customer controls — EC2 public DNS, load balancers, API Gateway, S3 buckets, RDS/OpenSearch endpoints — so an agent could send data it reads to a server someone else runs on AWS, and allowed model endpoints receive whatever the agent reads. Your own policy adds whatever it allows (typically Git hosts and package registries). The restricted, read-only, short-lived role is the main control; replace `awsDomains` wildcards with exact hosts if egress matters for your use. Organizations data is only readable from the management or a delegated administrator account.

Resume applies the current list to an existing sandbox before checking it, so allowlist changes take effect on the next resume.

## Workspace and lifecycle

**Empty mode is the default.** Without a path, the agent starts in an empty workspace with no host files transferred — suited to AWS investigation that needs no source code. Files created there persist across resume but are lost when the sandbox is destroyed. The current directory is never mounted implicitly (it only supplies the default name); a relative path is resolved from the directory you ran mise in.

**Project mode** is selected by passing a path after the agent, mounting that directory for host edits — the agent can read and change files there immediately, including uncommitted and ignored ones. Don't choose a directory containing credentials or private keys; host home and its ancestors are rejected as project roots.

In project mode the launcher runs `mise install` in the workspace on launch and on every resume, before any AWS session is handed over, so the project's mise tools are ready when the agent starts. If it fails, for example because the network policy blocks a download, you get a warning and the launch carries on; run `mise install` in the sandbox to see why. The templates put mise's shims first on PATH for the agent and for every shell, so `mise.toml`, `.tool-versions`, `.ruby-version`, `.node-version` and `rust-toolchain.toml` choose the versions without needing `mise activate` (the templates enable those idiomatic version files for Ruby, Node and Rust, which mise otherwise ignores). Bootstrap commands run with the template's own Node, not a project's.

Like sbx, a sandbox is named `<agent>-<directory>` after the project directory, or after the current directory in empty mode (lowercased, with other characters replaced by hyphens); `--name` chooses any other lowercase name. Running the same launch again reattaches to that sandbox, but only if the agent, path and AWS profile, role and region all match — otherwise it is refused, so pick another `--name` or remove the old sandbox. A name already used by a sandbox this launcher didn't create is refused too.

Each launch prints its name and credential expiry. The sandbox is retained after the agent exits:

```sh
mise run sbx run --name <name>  # reattach
mise run sbx rm <name>
mise run sbx rm --force <name>  # also forgets one already removed with sbx directly
```

Resume reattaches to a ready session, first repeating the host checks (sbx version/settings, stored secrets, network policy). If less than `renewWithinSeconds` (default 15 minutes) of the AWS session remain, it reassumes the restricted role on the host and hands the new session to the sandbox; new shells then use it. This needs a valid upstream `aws login` and only happens on resume, not while an agent is running. `mise run sbx run --name <name>` reattaches from anywhere — `--name` is recognized regardless of position, so `mise run sbx run <agent> --name <name>` also reattaches, with `<agent>` only confirming a match (a mismatch is rejected). The same command without mise skips the checks and never renews credentials. A sandbox is managed when the launcher holds live session metadata for it, whatever its name; a bare `--name` for any other sandbox is passed straight through to `sbx`.

Destroy stops the active session and removes the sandbox. Mounted project files remain on the host; files created only in an empty sandbox are lost. Failed launches are stopped and retained for inspection. Only recorded launcher sessions can be destroyed through these tasks.

Non-secret metadata lives under `~/.readonly-agent-sandbox` (override with `READONLY_SANDBOX_STATE_DIR`); credentials are never written to host state. Sessions from the previous clone/collect launcher must be collected or destroyed with that version before upgrading.

## Running apps in the sandbox

The templates include compilers (`build-essential`, `pkg-config`) and the headers to build Ruby with mise and the native gems Rails apps commonly use: OpenSSL, libyaml, readline, zlib, GMP, libffi, gdbm, ncurses, PostgreSQL (`pg`), MySQL (`mysql2`) and SQLite; Rust's linker and `openssl-sys` need nothing more. Cargo builds into `/home/agent/.cache/cargo-target` (`CARGO_TARGET_DIR`) inside the sandbox, so a mounted project's `target/` isn't shared with host builds; that output is lost when the sandbox is removed. Package registries still need network allows, such as `**.rubygems.org` in `allowedHosts`; the launcher applies changes to that list on the next launch or resume, with no rebuild.

To reach an app from a host browser, start it listening on all interfaces, not just localhost, then publish its port while the sandbox is running. For a Rails app on port 3000, from host terminals:

```sh
mise run sbx exec -it <name> env BINDING=0.0.0.0 bin/setup   # sets up the app, then starts the server
mise run sbx ports <name> --publish 3000:3000                 # then open http://localhost:3000
mise run sbx ports <name>                                     # list published ports
mise run sbx ports <name> --unpublish 3000:3000
```

`bin/setup` installs gems, prepares the database and starts the server via `bin/dev`. Rails' development server listens only on localhost unless `BINDING` (or `-b`) says otherwise. `sbx exec` and `sbx ports` pass straight through to sbx; `exec` runs in the workspace with mise's shims on PATH. The default `tcp4` suits a server listening on `0.0.0.0`; a published port is inbound and unaffected by the sandbox's network policy.

## Development

```sh
npm ci --ignore-scripts
npm run check
node scripts/sandbox.ts --help
```

Tests use synthetic profiles and credentials — no model calls or AWS access. CI runs host checks on Windows, macOS, and Linux. Subprocesses use argument arrays without a shell. Host scripts and the Linux sandbox bootstrap are TypeScript.

Before production use, validate a real session in a controlled AWS account: permitted reads succeed, writes/further role assumption/prohibited reads fail, credentials expire, and mounted project edits appear on the host. Identity checks don't prove IAM policy correctness. Allowed model endpoints can receive any data the role can read.

## References

- [AWS login and process bridge](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sign-in.html)
- [AWS role profiles](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html)
- [AWS AssumeRole](https://docs.aws.amazon.com/cli/latest/reference/sts/assume-role.html)
- [Docker sandbox usage](https://docs.docker.com/ai/sandboxes/usage/)
- [Docker local network policy](https://docs.docker.com/ai/sandboxes/governance/access-controls/local/)
