/** Persisted 6-char instance suffix for unique agent registration names. */
import { randomBytes } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";

let cachedSuffix: string | null | undefined;

export function isInstanceSuffixDisabled(): boolean {
  const env =
    process.env.TAP_DISABLE_INSTANCE_SUFFIX ??
    process.env.TAP_DISABLE_LOCAL_AGENT_SUFFIX ??
    "";
  return ["1", "true", "yes"].includes(env.trim().toLowerCase());
}

function defaultInstanceFile(identityDir?: string): string {
  const explicit = process.env.TAP_INSTANCE_FILE?.trim();
  if (explicit) return explicit;

  const base = identityDir
    ? path.dirname(path.resolve(identityDir))
    : path.join(homedir(), ".tap");
  return path.join(base, "instance.json");
}

function generateSuffix(): string {
  return randomBytes(3).toString("hex");
}

async function loadFile(filePath: string): Promise<string | null> {
  try {
    const data = JSON.parse(await readFile(filePath, "utf8")) as { suffix?: string };
    const suffix = data.suffix?.trim();
    return suffix || null;
  } catch {
    return null;
  }
}

async function saveFile(filePath: string, suffix: string): Promise<void> {
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, `${JSON.stringify({ suffix }, null, 2)}\n`, { mode: 0o600 });
  try {
    await chmod(filePath, 0o600);
  } catch {
    /* windows */
  }
}

export async function getOrCreateInstanceSuffix(
  identityDir?: string,
): Promise<string | undefined> {
  if (isInstanceSuffixDisabled()) return undefined;

  const explicit = process.env.TAP_INSTANCE_SUFFIX?.trim();
  if (explicit) return explicit;

  if (cachedSuffix !== undefined) return cachedSuffix ?? undefined;

  const filePath = defaultInstanceFile(identityDir);
  const existing = await loadFile(filePath);
  if (existing) {
    cachedSuffix = existing;
    return existing;
  }

  const suffix = generateSuffix();
  await saveFile(filePath, suffix);
  cachedSuffix = suffix;
  return suffix;
}

/** Clear in-memory cache (tests). */
export function clearInstanceSuffixCache(): void {
  cachedSuffix = undefined;
}
