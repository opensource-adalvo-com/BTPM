// Phase 4D.14A.7A — SharePoint Tenant runtime resolver (Edge-only).
//
// Resolves the effective SharePoint site configuration (site_url, optional
// site_id) for a given Organization from the Tenant Integration
// `sharepoint / default`. Fails closed on any missing / blocked / invalid
// value. NEVER falls back to Global `BTPM_SP_*` env secrets. NEVER logs
// or returns config values, IDs, or Vault metadata.
//
// This resolver does NOT resolve Microsoft Graph credentials — the caller
// must resolve those separately via
// `resolveAndAcquireTenantMicrosoftGraph`.

// deno-lint-ignore-file no-explicit-any
import { createClient } from "npm:@supabase/supabase-js@2";
import {
  resolveTenantIntegrationSecretValue,
  TenantIntegrationSecretError,
} from "./tenantIntegrationSecrets.ts";

export type SharePointAction = "real_integration";

export type SharePointResolveErrorCode =
  | "organization_context_missing"
  | "organization_not_found"
  | "environment_action_blocked"
  | "integration_not_configured"
  | "integration_disabled"
  | "secret_missing"
  | "secret_blocked"
  | "site_url_invalid"
  | "site_id_invalid"
  | "configuration_unavailable";

export class TenantSharePointError extends Error {
  code: SharePointResolveErrorCode;
  constructor(code: SharePointResolveErrorCode, message: string) {
    super(message);
    this.name = "TenantSharePointError";
    this.code = code;
  }
}

const INTERNAL_MESSAGES: Record<SharePointResolveErrorCode, string> = {
  organization_context_missing: "Organization context is unavailable.",
  organization_not_found: "The Organization could not be resolved.",
  environment_action_blocked:
    "SharePoint access is not allowed for this Organization or environment.",
  integration_not_configured:
    "The SharePoint Tenant integration is not configured or is incomplete.",
  integration_disabled:
    "The SharePoint Tenant integration is not configured or is incomplete.",
  // deepcode ignore HardcodedNonCryptoSecret: <please specify a reason of ignoring this>
  secret_missing:
    "The SharePoint Tenant integration is not configured or is incomplete.",
  // deepcode ignore HardcodedNonCryptoSecret: <please specify a reason of ignoring this>
  secret_blocked:
    "SharePoint access is not allowed for this Organization or environment.",
  site_url_invalid:
    "The SharePoint Tenant integration configuration is invalid.",
  site_id_invalid:
    "The SharePoint Tenant integration configuration is invalid.",
  configuration_unavailable:
    "SharePoint configuration is temporarily unavailable.",
};

export function mapTenantSecretErrorToSharePointCode(
  code: "blocked" | "not_found" | "empty" | "malformed" | "resolver_unavailable",
): SharePointResolveErrorCode {
  switch (code) {
    case "blocked":
      return "secret_blocked";
    case "not_found":
    case "empty":
      return "secret_missing";
    case "malformed":
    case "resolver_unavailable":
      return "configuration_unavailable";
  }
}

export function classifyEnvironmentGateError(
  err: { code?: string | null } | null | undefined,
): SharePointResolveErrorCode {
  if ((err?.code ?? null) === "42501") return "environment_action_blocked";
  return "configuration_unavailable";
}

export function classifyOrganizationLookup(
  err: unknown,
  row: { tenant_id?: string | null } | null | undefined,
):
  | { ok: true; tenantId: string }
  | { ok: false; code: SharePointResolveErrorCode } {
  if (err) return { ok: false, code: "configuration_unavailable" };
  const tenantId = row?.tenant_id ?? null;
  if (!tenantId) return { ok: false, code: "organization_not_found" };
  return { ok: true, tenantId };
}

export function classifySharePointIntegrationLookup(
  err: unknown,
  row:
    | { id?: string | null; is_enabled?: boolean | null; status?: string | null }
    | null
    | undefined,
):
  | { ok: true; integrationId: string }
  | { ok: false; code: SharePointResolveErrorCode } {
  if (err) return { ok: false, code: "configuration_unavailable" };
  if (!row?.id) return { ok: false, code: "integration_not_configured" };
  if (!row.is_enabled || row.status !== "active") {
    return { ok: false, code: "integration_disabled" };
  }
  return { ok: true, integrationId: row.id };
}

/** Normalized SharePoint site URL derived from a Tenant configuration. */
export interface NormalizedSharePointSiteUrl {
  /** Full absolute URL, trailing slash trimmed. */
  href: string;
  /** Hostname, lowercased. */
  hostname: string;
  /** Path portion: `""` for root site, otherwise `/sites/<name>` etc, no trailing slash. */
  path: string;
  /** True when the path is `""` (root site of the tenant). */
  isRootSite: boolean;
}

/**
 * Parse and validate a SharePoint site URL. Rejects non-HTTPS, embedded
 * credentials, non-SharePoint hosts, and URLs with query strings or
 * fragments. Returns a normalized shape. Throws nothing — callers must
 * inspect the returned discriminant.
 */
export function parseAndNormalizeSharePointSiteUrl(
  raw: unknown,
):
  | { ok: true; value: NormalizedSharePointSiteUrl }
  | { ok: false; code: "site_url_invalid" } {
  if (typeof raw !== "string") return { ok: false, code: "site_url_invalid" };
  const trimmed = raw.trim();
  if (trimmed.length === 0) return { ok: false, code: "site_url_invalid" };
  let u: URL;
  try {
    u = new URL(trimmed);
  } catch {
    return { ok: false, code: "site_url_invalid" };
  }
  if (u.protocol !== "https:") return { ok: false, code: "site_url_invalid" };
  if (u.username.length > 0 || u.password.length > 0) {
    return { ok: false, code: "site_url_invalid" };
  }
  if (u.search.length > 0 || u.hash.length > 0) {
    return { ok: false, code: "site_url_invalid" };
  }
  const hostname = u.hostname.toLowerCase();
  if (!hostname.endsWith(".sharepoint.com")) {
    return { ok: false, code: "site_url_invalid" };
  }
  // Path normalization: strip trailing slash; `/` -> `""` (root site).
  let path = u.pathname;
  if (path.endsWith("/") && path.length > 1) path = path.slice(0, -1);
  if (path === "/") path = "";
  // If a path is present, it must look like `/sites/<segment>` or
  // `/teams/<segment>` (Graph accepts both via site-by-path). We do not
  // want to silently accept `/foo/bar` or arbitrary paths.
  if (path.length > 0) {
    const segments = path.split("/").filter((s) => s.length > 0);
    if (segments.length < 2) return { ok: false, code: "site_url_invalid" };
    const kind = segments[0].toLowerCase();
    if (kind !== "sites" && kind !== "teams") {
      return { ok: false, code: "site_url_invalid" };
    }
    // Site segment must be non-empty and URL-safe-ish (no whitespace).
    if (segments[1].length === 0 || /\s/.test(segments[1])) {
      return { ok: false, code: "site_url_invalid" };
    }
  }
  const href = `https://${hostname}${path}`;
  return {
    ok: true,
    value: { href, hostname, path, isRootSite: path.length === 0 },
  };
}

const GUID_RE =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/**
 * Whether a Graph site-ID string is a supported shape:
 *   - composite: `{hostname},{guid},{guid}`
 *   - bare GUID
 *   - root-site identifier: `{hostname}` or `{hostname},root`
 * Anything else (PnP permission records, opaque base64, arbitrary text)
 * is rejected.
 */
export function isSupportedGraphSiteId(raw: unknown): boolean {
  if (typeof raw !== "string") return false;
  const v = raw.trim();
  if (v.length === 0) return false;
  // Composite: host,guid,guid
  if (v.includes(",")) {
    const parts = v.split(",");
    if (parts.length === 2) {
      // hostname,root
      const [host, root] = parts;
      if (root.trim().toLowerCase() !== "root") return false;
      return host.trim().toLowerCase().endsWith(".sharepoint.com");
    }
    if (parts.length !== 3) return false;
    const [host, g1, g2] = parts;
    if (!host.trim().toLowerCase().endsWith(".sharepoint.com")) return false;
    return GUID_RE.test(g1.trim()) && GUID_RE.test(g2.trim());
  }
  // Bare GUID
  if (GUID_RE.test(v)) return true;
  // Bare hostname (root site)
  if (/^[a-z0-9.-]+\.sharepoint\.com$/i.test(v)) return true;
  return false;
}

/**
 * Safe browser-facing error mapper. Collapses internal codes to fixed
 * public contracts and never contains identifiers or raw messages.
 */
export function toSafeSharePointPublicError(error: unknown): {
  error:
    | "sharepoint_not_configured"
    | "sharepoint_access_blocked"
    | "sharepoint_configuration_invalid"
    | "sharepoint_configuration_unavailable";
  note: string;
} {
  const code: SharePointResolveErrorCode = error instanceof TenantSharePointError
    ? error.code
    : "configuration_unavailable";
  switch (code) {
    case "environment_action_blocked":
    case "secret_blocked":
      return {
        error: "sharepoint_access_blocked",
        note:
          "SharePoint access is not allowed for this Organization or environment.",
      };
    case "site_url_invalid":
    case "site_id_invalid":
      return {
        error: "sharepoint_configuration_invalid",
        note: "The SharePoint Tenant integration configuration is invalid.",
      };
    case "integration_not_configured":
    case "integration_disabled":
    case "secret_missing":
      return {
        error: "sharepoint_not_configured",
        note:
          "The SharePoint Tenant integration is not configured or is incomplete.",
      };
    case "organization_context_missing":
    case "organization_not_found":
    case "configuration_unavailable":
    default:
      return {
        error: "sharepoint_configuration_unavailable",
        note: "SharePoint configuration is temporarily unavailable.",
      };
  }
}

export interface SharePointRuntimeConfig {
  tenantId: string;
  organizationId: string;
  integrationId: string;
  integrationName: string;
  siteUrl: NormalizedSharePointSiteUrl;
  siteId: string | null;
}

export interface ResolveSharePointArgs {
  organizationId: string;
  action: SharePointAction;
  reason?: string;
  functionName?: string;
  requestId?: string;
}

function requireEnv(name: string): string {
  const v = Deno.env.get(name);
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}

function serviceClient() {
  return createClient(
    requireEnv("SUPABASE_URL"),
    requireEnv("SUPABASE_SERVICE_ROLE_KEY"),
    { auth: { persistSession: false, autoRefreshToken: false } },
  );
}

async function resolveSpSecret(
  tenantId: string,
  organizationId: string,
  secretName: "site_url" | "site_id",
  args: ResolveSharePointArgs,
  required: boolean,
): Promise<string | null> {
  try {
    const r = await resolveTenantIntegrationSecretValue({
      tenantId,
      organizationId,
      integrationKind: "sharepoint",
      secretName,
      integrationName: "default",
      reason: args.reason,
      functionName: args.functionName,
      requestId: args.requestId,
    });
    return r.value;
  } catch (e) {
    if (e instanceof TenantIntegrationSecretError) {
      // For optional secrets, `not_found`/`empty` returns null (absent).
      if (!required && (e.code === "not_found" || e.code === "empty")) {
        return null;
      }
      const mapped = mapTenantSecretErrorToSharePointCode(e.code);
      throw new TenantSharePointError(mapped, INTERNAL_MESSAGES[mapped]);
    }
    throw new TenantSharePointError(
      "configuration_unavailable",
      INTERNAL_MESSAGES.configuration_unavailable,
    );
  }
}

export async function resolveTenantSharePointRuntimeConfig(
  args: ResolveSharePointArgs,
): Promise<SharePointRuntimeConfig> {
  if (!args?.organizationId) {
    throw new TenantSharePointError(
      "organization_context_missing",
      INTERNAL_MESSAGES.organization_context_missing,
    );
  }
  if (args.action !== "real_integration") {
    throw new TenantSharePointError(
      "environment_action_blocked",
      INTERNAL_MESSAGES.environment_action_blocked,
    );
  }

  const supabase = serviceClient();

  const { data: orgRow, error: orgErr } = await supabase
    .from("organizations")
    .select("id, tenant_id")
    .eq("id", args.organizationId)
    .maybeSingle();
  const orgClass = classifyOrganizationLookup(orgErr, orgRow);
  if (!orgClass.ok) {
    throw new TenantSharePointError(
      orgClass.code,
      INTERNAL_MESSAGES[orgClass.code],
    );
  }
  const tenantId = orgClass.tenantId;

  const { error: gateErr } = await supabase.rpc(
    "assert_environment_action_allowed",
    {
      _organization_id: args.organizationId,
      _action: args.action,
      _reason: args.reason ?? "sharepoint-runtime",
    },
  );
  if (gateErr) {
    const gateCode = classifyEnvironmentGateError(
      gateErr as { code?: string | null },
    );
    throw new TenantSharePointError(gateCode, INTERNAL_MESSAGES[gateCode]);
  }

  const { data: integ, error: integErr } = await supabase
    .from("tenant_integrations")
    .select("id, name, is_enabled, status")
    .eq("tenant_id", tenantId)
    .eq("kind", "sharepoint")
    .eq("name", "default")
    .maybeSingle();
  const integClass = classifySharePointIntegrationLookup(integErr, integ);
  if (!integClass.ok) {
    throw new TenantSharePointError(
      integClass.code,
      INTERNAL_MESSAGES[integClass.code],
    );
  }
  const integrationId = integClass.integrationId;
  const integrationName = (integ?.name as string) ?? "default";

  const rawSiteUrl = await resolveSpSecret(
    tenantId,
    args.organizationId,
    "site_url",
    args,
    true,
  );
  if (rawSiteUrl === null || rawSiteUrl.length === 0) {
    throw new TenantSharePointError(
      "secret_missing",
      INTERNAL_MESSAGES.secret_missing,
    );
  }
  const parsedUrl = parseAndNormalizeSharePointSiteUrl(rawSiteUrl);
  if (!parsedUrl.ok) {
    throw new TenantSharePointError(
      "site_url_invalid",
      INTERNAL_MESSAGES.site_url_invalid,
    );
  }

  const rawSiteId = await resolveSpSecret(
    tenantId,
    args.organizationId,
    "site_id",
    args,
    false,
  );
  let siteId: string | null = null;
  if (rawSiteId !== null) {
    const trimmed = rawSiteId.trim();
    if (trimmed.length > 0) {
      if (!isSupportedGraphSiteId(trimmed)) {
        throw new TenantSharePointError(
          "site_id_invalid",
          INTERNAL_MESSAGES.site_id_invalid,
        );
      }
      siteId = trimmed;
    }
  }

  return {
    tenantId,
    organizationId: args.organizationId,
    integrationId,
    integrationName,
    siteUrl: parsedUrl.value,
    siteId,
  };
}
