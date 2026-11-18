// Remembers the last opened org id (not sensitive) so "/" can resume there.
const KEY = "secureai:last-org";

export function getLastOrg(): string | null {
  try {
    return localStorage.getItem(KEY);
  } catch {
    return null;
  }
}

export function setLastOrg(orgId: string) {
  try {
    localStorage.setItem(KEY, orgId);
  } catch {
    /* storage disabled */
  }
}
