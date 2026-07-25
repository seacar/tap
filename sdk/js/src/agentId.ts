/** Resolve logical agent names with an optional per-install instance suffix. */

import { isInstanceSuffixDisabled } from "./instanceSuffix.js";

export function resolveAgentId(logicalId: string, instanceSuffix?: string): string {
  if (isInstanceSuffixDisabled() || !instanceSuffix) {
    return logicalId;
  }

  const safe = instanceSuffix.replace(/\//g, "_").replace(/\\/g, "_");
  return `${logicalId}-${safe}`;
}
