// Optional real-microVM test. No AWS credentials, model calls, or host policy
// changes. Only randomly named test sandboxes are removed by its cleanup.
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hostEnvironment, run, successful } from "../scripts/lib/process.ts";
import { checkSbxVersion, configuration, unexpectedSecrets } from "../scripts/lib/sandbox.ts";

const env = hostEnvironment();
const dir = await mkdtemp(join(tmpdir(), "readonly-runtime-"));
const { runtime } = await configuration();
async function call(tool: string, args: string[], cwd?: string, input?: string) {
  return successful(
    await run(tool, args, { env, cwd, input, timeout: 600_000 }),
    `Runtime test ${tool}`,
  );
}
const cliVersion = await call("sbx", ["version"]);
checkSbxVersion(cliVersion, runtime.minSbxVersion);
console.log(`Testing against ${cliVersion} (minimum ${runtime.minSbxVersion}).`);
try {
  for (const agent of ["claude", "codex"]) {
    const project = join(dir, `project-${agent}`);
    await mkdir(project);
    await writeFile(join(project, "example.txt"), "initial\n");
    const name = `readonly-test-${agent}-${randomBytes(6).toString("hex")}`;
    // Same host-side guard as launch: stored secrets are injected into every sandbox.
    const secrets = unexpectedSecrets(JSON.parse(await call("sbx", ["secret", "ls", "--json"])));
    if (secrets.length) throw new Error(`Remove stored sbx secrets first: ${secrets.join(", ")}`);
    try {
      await call("sbx", [
        "create",
        "--name",
        name,
        "--skills",
        "off",
        "--static-mcp=",
        "--deny-network",
        "**",
        "--pull",
        "never",
        "--template",
        runtime.templates[agent].tag,
        agent,
        project,
      ]);
      const info = JSON.parse(await call("sbx", ["inspect", name, "--json"]));
      assert.deepEqual(info.runtime_mounts, []);
      assert.ok(info.workspace);
      // The daemon, not just the CLI, must meet the minimum and match the CLI:
      // some sbx changes apply only after a daemon restart.
      checkSbxVersion(info.daemon_version, runtime.minSbxVersion);
      assert.equal(/v\d+\.\d+\.\d+/.exec(cliVersion)?.[0], info.daemon_version);
      assert.deepEqual(info.kits, []);
      // Copy the current bootstrap so edits can be tested before rebuilding.
      await call("sbx", ["cp", "sandbox/bootstrap.ts", `${name}:/tmp/bootstrap.ts`]);
      const boot = (command: string) =>
        call("sbx", ["exec", name, "node", "/tmp/bootstrap.ts", command]);
      // The same fresh-sandbox checks a real launch runs first. sbx's GH_TOKEN
      // proxy placeholder is present and tolerated.
      assert.equal(
        await call("sbx", ["exec", name, "bash", "-c", '[ -n "$GH_TOKEN" ] && echo set']),
        "set",
      );
      await boot("check");
      // Skills a kit could install despite --skills off stop the launch.
      const skill = "/home/agent/.claude/skills/planted/SKILL.md";
      await call("sbx", [
        "exec",
        name,
        "bash",
        "-c",
        `mkdir -p "$(dirname ${skill})" && touch ${skill}`,
      ]);
      const planted = await run("sbx", ["exec", name, "node", "/tmp/bootstrap.ts", "check"], {
        env,
      });
      assert.notEqual(planted.code, 0);
      await call("sbx", ["exec", name, "rm", "-r", "/home/agent/.claude/skills/planted"]);
      await boot("check");
      await boot("probe-network");
      await call("sbx", [
        "exec",
        name,
        "node",
        "-e",
        'const fs=require("fs");fs.writeFileSync("example.txt","changed\\n");',
      ]);
      assert.equal(await readFile(join(project, "example.txt"), "utf8"), "changed\n");
      // A synthetic aws executable validates the stdin-to-environment transport;
      // network is still deny-all, and no real AWS session is involved.
      const fakeDir = join(dir, `fake-${agent}`);
      await mkdir(fakeDir);
      const expected = {
        Account: "222222222222",
        Arn: "arn:aws:sts::222222222222:assumed-role/ReadOnlyRole/agent-runtime-test",
        UserId: "AROEXAMPLE:agent-runtime-test",
      };
      await writeFile(
        join(fakeDir, "aws"),
        '#!/usr/bin/env node\nif(!process.env.AWS_ACCESS_KEY_ID?.startsWith("ASIA_RUNTIME_TEST"))process.exit(2);console.log(' +
          JSON.stringify(JSON.stringify(expected)) +
          ");\n",
      );
      await call("sbx", ["cp", fakeDir, `${name}:/tmp/fake-aws`]);
      await call("sbx", ["exec", name, "chmod", "755", "/tmp/fake-aws/aws"]);
      const inject = (accessKey: string) =>
        call(
          "sbx",
          [
            "exec",
            "-i",
            "--env",
            "PATH=/tmp/fake-aws:/usr/local/bin:/usr/bin:/bin",
            name,
            "node",
            "/tmp/bootstrap.ts",
            "inject",
          ],
          undefined,
          JSON.stringify({
            credentials: {
              AccessKeyId: accessKey,
              SecretAccessKey: "EXAMPLE_RUNTIME_SECRET",
              SessionToken: "EXAMPLE_RUNTIME_TOKEN",
              Expiration: new Date(Date.now() + 3600_000).toISOString(),
            },
            identity: expected,
            region: "us-west-2",
          }),
        );
      const verify = join(dir, `verify-${agent}.ts`);
      await writeFile(
        verify,
        'import assert from "node:assert/strict";import{statSync}from"node:fs";assert.equal(process.env.AWS_ACCESS_KEY_ID,process.argv[2]);assert.equal(process.env.AWS_PROFILE,undefined);assert.equal(process.env.SSH_AUTH_SOCK,undefined);assert.equal(process.env.GH_TOKEN,undefined);assert.equal(statSync("/home/agent/.readonly-session/aws.sh").mode & 0o777,0o600);console.log("session-ok");',
      );
      await call("sbx", ["cp", verify, `${name}:/tmp/verify.ts`]);
      // Launch, then a resume-style renewal: new shells see the renewed session
      // and the persistent source line is not duplicated.
      for (const accessKey of ["ASIA_RUNTIME_TEST", "ASIA_RUNTIME_TEST_RENEWED"]) {
        await inject(accessKey);
        assert.equal(
          await call("sbx", ["exec", name, "bash", "-lc", `node /tmp/verify.ts ${accessKey}`]),
          "session-ok",
        );
      }
      assert.equal(
        await call("sbx", [
          "exec",
          name,
          "sudo",
          "grep",
          "-cxF",
          ". '/home/agent/.readonly-session/aws.sh'",
          "/etc/sandbox-persistent.sh",
        ]),
        "1",
      );
      console.log(
        `${agent}: mounted edits, proxy denial, synthetic credential handoff, and persistent environment passed.`,
      );
    } finally {
      await call("sbx", ["rm", "--force", name]);
    }
  }
} finally {
  await rm(dir, { recursive: true });
}
