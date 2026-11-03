# Read-only AWS agent sandboxes

Run Claude or Codex in a local Docker Sandbox with temporary access to a restricted AWS role. Use your existing AWS profiles and browser login, with an empty workspace for investigations or a local project for coding.

## Before you start

Install:

- [mise](https://mise.jdx.dev/getting-started.html) and Node 24 (`mise install` below installs Node).
- Docker with Linux image builds and [Docker Sandboxes (`sbx`)](https://docs.docker.com/ai/sandboxes/usage/) 0.46.0 or later. Install sbx with `brew install docker/tap/sbx`, `winget install Docker.sbx`, or `docker-sbx` from Docker's apt repository. Restart the sbx daemon after an upgrade.
- AWS CLI v2.32+ if you want AWS access.

Configure your agent's authentication through Docker's host-side setup. Do not mount agent home directories into the sandbox. Use Docker's recommended `balanced` network policy when prompted during setup.

For AWS access, you need an existing account profile with `role_arn`, `source_profile` and a region, plus permission to assume a restricted role in that account (by default, `ReadOnlyRole`). The launcher does not create roles or permissions. Static AWS access keys are not supported. See the [example profiles](examples/aws-config) and [detailed AWS requirements](TECHNICAL.md#runtime-and-aws-requirements) if your setup differs.

## Set up

Run these commands from this repository:

```sh
mise install
mise run build_all
```

The first build can take several minutes. To build only one agent, use `mise run build claude` or `mise run build codex`.

## Start an agent

Log in to AWS, then launch with your account profile:

```sh
aws login --profile browser-login
mise run sbx run claude --profile workload
```

Replace `browser-login` and `workload` with your own profile names. Use `codex` instead of `claude` to launch Codex. All account IDs and profile names in the examples are fictional.

With no project path, the agent gets an empty workspace; your current directory is not mounted. To let the agent work on local files, pass the project path:

```sh
mise run sbx run codex /path/to/project --profile workload
```

**The agent can immediately read and edit files in that directory**, including uncommitted and ignored files. Choose a project directory without credentials or private keys. Your home directory and its ancestors cannot be mounted as project roots.

To run without AWS access, omit `--profile`:

```sh
mise run sbx run claude /path/to/project
```

Common options:

| Option | Use |
| --- | --- |
| `--name my-box` | Choose a sandbox name. |
| `--role agents/RestrictedReadOnlyRole` | Use a different restricted role name or path. |
| `--region us-west-2` | Override the profile's region. |
| `--source-profile other-source` | Use a different source profile for AWS login credentials. |

The AWS options require `--profile`. Without `--name`, the name is `<agent>-<directory>`, using the project directory or, for an empty workspace, the current directory. The launcher prints the name and AWS credential expiry at startup.

## Resume or remove a sandbox

Exiting the agent keeps the sandbox and its files. List, resume or remove it with:

```sh
mise run sbx ls
mise run sbx run --name my-box
mise run sbx rm my-box
```

Repeating the original launch command also resumes it when the agent, project path and AWS settings match. Use a new `--name` for a different setup.

AWS sessions normally last one hour. Resume through `mise run sbx run` to renew credentials when they are near expiry; log in to AWS again first if needed. Credentials do not refresh while an agent is running. Running `sbx run` directly skips the launcher's checks and renewal.

Removing a sandbox deletes files stored only inside it. Mounted project files remain on your host. If you already removed a sandbox with sbx directly, `mise run sbx rm --force my-box` clears the launcher's saved record.

## Check your setup

```sh
# Inspect profile settings without contacting AWS or Docker
mise run preview claude --profile workload

# Check Docker, network policy and AWS role access
mise run doctor --profile workload --agent claude

# Check the host setup without AWS
mise run doctor

# Show all launcher options
node scripts/sandbox.ts --help
```

Use an AWS role whose permissions match the data you intend the agent to read. A read-only role can still expose sensitive data, and the agent can send what it reads to its model provider or other allowed services. Review the launcher's notices about SSH keys, stored service secrets and MCP servers: these can grant access beyond AWS. See [security and network details](TECHNICAL.md#network-policy) for configuration and limits.

## Running an app

In a project sandbox, the launcher tries `mise install` on launch and resume. If tool installation warns or fails, run `mise install` inside the sandbox to diagnose it. For blocked downloads, see [network configuration](TECHNICAL.md#network-policy).

Start your app listening on `0.0.0.0`, then publish its port from a host terminal. For a Rails project whose `bin/setup` starts the server:

```sh
mise run sbx exec -it my-box docker compose up -d db
mise run sbx exec -it my-box env BINDING=0.0.0.0 bin/setup
```

In another host terminal:

```sh
mise run sbx ports my-box --publish 3000:3000
# Open http://localhost:3000
mise run sbx ports my-box --unpublish 3000:3000
```

Other sbx commands, such as `exec`, `ports` and `ls`, pass through unchanged via `mise run sbx`. See the [Docker Sandboxes usage guide](https://docs.docker.com/ai/sandboxes/usage/) for more commands.

For credential handling, network rules, template maintenance, adding agents and development, see [TECHNICAL.md](TECHNICAL.md).
