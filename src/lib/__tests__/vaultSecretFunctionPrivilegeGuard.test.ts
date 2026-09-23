/**
 * SEC — Vault-touching functions must never be executable by browser roles.
 *
 * Replays every CREATE FUNCTION / GRANT / REVOKE ... ON FUNCTION statement in
 * supabase/migrations in order and asserts that no function whose body reads
 * or writes Supabase Vault ends up executable by PUBLIC, anon or authenticated.
 * A newly created function starts with the Postgres + Supabase default ACL
 * (PUBLIC, anon, authenticated, service_role); CREATE OR REPLACE of an existing
 * function keeps its ACL. Functions are keyed by qualified name (overloads are
 * merged, which only makes the check stricter).
 */
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const MIGRATIONS_DIR = resolve(process.cwd(), "supabase/migrations");
const BROWSER_ROLES = ["public", "anon", "authenticated"] as const;
const VAULT_ACCESS = /\bvault\.(decrypted_secrets|secrets|create_secret|update_secret)\b/i;

const MIGRATIONS = readdirSync(MIGRATIONS_DIR)
  .filter((n) => n.endsWith(".sql"))
  .sort()
  .map((name) => ({ name, sql: readFileSync(resolve(MIGRATIONS_DIR, name), "utf8") }));

const normalizeName = (n: string) => {
  const name = n.replace(/"/g, "").toLowerCase();
  return name.includes(".") ? name : `public.${name}`;
};

type Event =
  | { kind: "create"; fn: string; orReplace: boolean; body: string }
  | { kind: "grant" | "revoke"; fn: string; roles: string[] };

function parseEvents(sql: string): { index: number; event: Event }[] {
  const events: { index: number; event: Event }[] = [];

  const createRe = /CREATE\s+(OR\s+REPLACE\s+)?FUNCTION\s+([\w."]+)\s*\(/gi;
  for (const m of sql.matchAll(createRe)) {
    const start = m.index!;
    const asTag = /\bAS\s+(\$[\w]*\$)/i.exec(sql.slice(start));
    let body = "";
    if (asTag) {
      const bodyStart = start + asTag.index + asTag[0].length;
      const bodyEnd = sql.indexOf(asTag[1], bodyStart);
      body = sql.slice(bodyStart, bodyEnd === -1 ? undefined : bodyEnd);
    }
    events.push({
      index: start,
      event: { kind: "create", fn: normalizeName(m[2]), orReplace: !!m[1], body },
    });
  }

  const aclRe =
    /\b(GRANT|REVOKE)\s+[\w\s,]+?\s+ON\s+FUNCTION\s+([\w."]+)\s*\([\s\S]*?\)\s+(TO|FROM)\s+([\w\s,"]+?)\s*(?:CASCADE|RESTRICT)?\s*;/gi;
  for (const m of sql.matchAll(aclRe)) {
    events.push({
      index: m.index!,
      event: {
        kind: m[1].toLowerCase() as "grant" | "revoke",
        fn: normalizeName(m[2]),
        roles: m[4].split(",").map((r) => r.replace(/"/g, "").trim().toLowerCase()),
      },
    });
  }

  return events.sort((a, b) => a.index - b.index);
}

function replay() {
  const acl = new Map<string, Set<string>>();
  const vaultFns = new Set<string>();
  for (const { sql } of MIGRATIONS) {
    for (const { event } of parseEvents(sql)) {
      if (event.kind === "create") {
        if (VAULT_ACCESS.test(event.body)) vaultFns.add(event.fn);
        if (!event.orReplace || !acl.has(event.fn)) {
          acl.set(event.fn, new Set(["public", "anon", "authenticated", "service_role"]));
        }
        continue;
      }
      const roles = acl.get(event.fn) ?? new Set<string>();
      for (const r of event.roles) {
        if (event.kind === "grant") roles.add(r);
        else roles.delete(r);
      }
      acl.set(event.fn, roles);
    }
  }
  return { acl, vaultFns };
}

describe("SEC Vault-touching function privilege contract", () => {
  const { acl, vaultFns } = replay();

  it("detects the known Vault-reading functions", () => {
    for (const fn of [
      "public.resolve_effective_integration_secret_value",
      "public.btpm_decrypt",
      "public.btpm_encrypt_v2",
      "public.admin_store_tenant_secret",
    ]) expect(vaultFns).toContain(fn);
  });

  it("never leaves a Vault-touching function executable by PUBLIC, anon or authenticated", () => {
    const exposed = [...vaultFns]
      .map((fn) => ({ fn, roles: BROWSER_ROLES.filter((r) => acl.get(fn)?.has(r)) }))
      .filter((e) => e.roles.length > 0);
    expect(exposed).toEqual([]);
  });

  it("keeps the integration secret resolvers service-role only", () => {
    for (const fn of [
      "public.resolve_effective_integration_secret_value",
      "public.resolve_effective_integration_secret_ref",
    ]) {
      expect([...(acl.get(fn) ?? [])].sort()).toEqual(["service_role"]);
    }
  });
});
