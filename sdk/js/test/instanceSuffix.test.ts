#!/usr/bin/env tsx
/** Unit tests for instance suffix and agent name resolution. */
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { resolveAgentId } from "../src/agentId.js";
import {
  clearInstanceSuffixCache,
  getOrCreateInstanceSuffix,
  isInstanceSuffixDisabled,
} from "../src/instanceSuffix.js";

async function withTempDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = await mkdtemp(path.join(tmpdir(), "tap-instance-test-"));
  try {
    await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function withEnv(
  vars: Record<string, string | undefined>,
  fn: () => Promise<void>,
): Promise<void> {
  const previous = new Map<string, string | undefined>();
  for (const [key, value] of Object.entries(vars)) {
    previous.set(key, process.env[key]);
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  clearInstanceSuffixCache();
  try {
    await fn();
  } finally {
    for (const [key, value] of previous.entries()) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    clearInstanceSuffixCache();
  }
}

async function main(): Promise<void> {
  assert.equal(resolveAgentId("finance-bot-v1", "a3f2b1"), "finance-bot-v1-a3f2b1");
  assert.equal(resolveAgentId("finance-bot-v1"), "finance-bot-v1");

  await withEnv({ TAP_DISABLE_INSTANCE_SUFFIX: "1" }, async () => {
    assert.ok(isInstanceSuffixDisabled());
    assert.equal(resolveAgentId("finance-bot-v1", "a3f2b1"), "finance-bot-v1");
  });

  await withEnv({ TAP_DISABLE_LOCAL_AGENT_SUFFIX: "1" }, async () => {
    assert.ok(isInstanceSuffixDisabled());
  });

  await withEnv({ TAP_INSTANCE_SUFFIX: "ci0001" }, async () => {
    await withTempDir(async (dir) => {
      const identityDir = path.join(dir, "identities");
      const suffix = await getOrCreateInstanceSuffix(identityDir);
      assert.equal(suffix, "ci0001");
      assert.equal(resolveAgentId("claims-adjuster", suffix), "claims-adjuster-ci0001");
    });
  });

  await withEnv({}, async () => {
    await withTempDir(async (dir) => {
      const identityDir = path.join(dir, "identities");
      const instanceFile = path.join(dir, "instance.json");

      const first = await getOrCreateInstanceSuffix(identityDir);
      assert.ok(first);
      assert.match(first!, /^[0-9a-f]{6}$/);

      const second = await getOrCreateInstanceSuffix(identityDir);
      assert.equal(second, first);

      const onDisk = JSON.parse(await readFile(instanceFile, "utf8")) as { suffix: string };
      assert.equal(onDisk.suffix, first);
    });
  });

  console.log("ok - instance suffix tests passed");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
