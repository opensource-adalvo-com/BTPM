// Phase 4D.14A.6A — Microsoft Graph Tenant runtime resolver (Edge-only).
//
// Resolves the effective Microsoft Graph credential (tenant_id, client_id,
// client_secret) for a given Organization from the Tenant Integration
// `microsoft_graph / default`. Fails closed on any missing / blocked /
// invalid value. NEVER falls back to Global `M365_*` env secrets. NEVER
// logs or returns secret material, IDs, or Vault metadata.

// deno-lint-ignore-file no-explicit-any
import { createClient } from "npm:@supabase/supabase-js@2";
import {
  resolveTenantIntegrationSecretValue,
  TenantIntegrationSecretError,
} from "./tenantIntegrationSecrets.ts";

export type MicrosoftGraphAction = "real_integration";

export type MicrosoftGraphResolveErrorCode =
  | "organization_context_missing"
  | "organization_not_found"
  | "environment_action_blocked"
  | "integration_not_configured"
  | "integration_disabled"
  | "secret_missing"
  | "secret_blocked"
  | "identifier_invalid"
  | "configuration_unavailable";

export class TenantMicrosoftGraphError extends Error {
  code: MicrosoftGraphResolveErrorCode;
  constructor(code: MicrosoftGraphResolveErrorCode, message: string) {
    super(message);
    this.name = "TenantMicrosoftGraphError";
    this.code = code;
  }
}

const INTERNAL_MESSAGES: Record<MicrosoftGraphResolveErrorCode, string> = {
  organization_context_missing: "Organization context is unavailable.",
  organization_not_found: "The Organization could not be resolved.",
  environment_action_blocked:
    "Microsoft Graph access is not allowed for this Organization or environment.",
  integration_not_configured:
    "The Microsoft Graph Tenant integration is not configured or is incomplete.",
  integration_disabled:
    "The Microsoft Graph Tenant integration is not configured or is incomplete.",
  // deepcode ignore HardcodedNonCryptoSecret: <please specify a reason of ignoring this>
  secret_missing:
    "The Microsoft Graph Tenant integration is not configured or is incomplete.",
  // deepcode ignore HardcodedNonCryptoSecret: <please specify a reason of ignoring this>
  secret_blocked:
    "Microsoft Graph access is not allowed for this Organization or environment.",
  identifier_invalid:
    "The Microsoft Graph Tenant integration configuration is invalid.",
  configuration_unavailable:
    "Microsoft Graph configuration is temporarily unavailable.",
};

export function mapTenantSecretErrorToGraphCode(
  code: "blocked" | "not_found" | "empty" | "malformed" | "resolver_unavailable",
): MicrosoftGraphResolveErrorCode {
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
): MicrosoftGraphResolveErrorCode {
  if ((err?.code ?? null) === "42501") return "environment_action_blocked";
  return "configuration_unavailable";
}

export function classifyOrganizationLookup(
  err: unknown,
  row: { tenant_id?: string | null } | null | undefined,
):
  | { ok: true; tenantId: string }
  | { ok: false; code: MicrosoftGraphResolveErrorCode } {
  if (err) return { ok: false, code: "configuration_unavailable" };
  const tenantId = row?.tenant_id ?? null;
  if (!tenantId) return { ok: false, code: "organization_not_found" };
  return { ok: true, tenantId };
}

export function classifyGraphIntegrationLookup(
  err: unknown,
  row:
    | { id?: string | null; is_enabled?: boolean | null; status?: string | null }
    | null
    | undefined,
):
  | { ok: true; integrationId: string }
  | { ok: false; code: MicrosoftGraphResolveErrorCode } {
  if (err) return { ok: false, code: "configuration_unavailable" };
  if (!row?.id) return { ok: false, code: "integration_not_configured" };
  if (!row.is_enabled || row.status !== "active") {
    return { ok: false, code: "integration_disabled" };
  }
  return { ok: true, integrationId: row.id };
}

const GUID_RE =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

export function isValidGuid(v: unknown): boolean {
  return typeof v === "string" && GUID_RE.test(v.trim());
}

/**
 * Safe browser-facing error mapper. Collapses internal codes to four fixed
 * public contracts and never contains identifiers, tokens, or raw messages.
 */
export function toSafeMicrosoftGraphPublicError(error: unknown): {
  error:
    | "microsoft_graph_not_configured"
    | "microsoft_graph_access_blocked"
    | "microsoft_graph_configuration_invalid"
    | "microsoft_graph_configuration_unavailable";
  note: string;
} {
  const code: MicrosoftGraphResolveErrorCode =
    error instanceof TenantMicrosoftGraphError
      ? error.code
      : "configuration_unavailable";
  switch (code) {
    case "environment_action_blocked":
    case "secret_blocked":
      return {
        error: "microsoft_graph_access_blocked",
        note:
          "Microsoft Graph access is not allowed for this Organization or environment.",
      };
    case "identifier_invalid":
      return {
        error: "microsoft_graph_configuration_invalid",
        note:
          "The Microsoft Graph Tenant integration configuration is invalid.",
      };
    case "integration_not_configured":
    case "integration_disabled":
    case "secret_missing":
      return {
        error: "microsoft_graph_not_configured",
        note:
          "The Microsoft Graph Tenant integration is not configured or is incomplete.",
      };
    case "organization_context_missing":
    case "organization_not_found":
    case "configuration_unavailable":
    default:
      return {
        error: "microsoft_graph_configuration_unavailable",
        note: "Microsoft Graph configuration is temporarily unavailable.",
      };
  }
}

export interface MicrosoftGraphRuntimeConfig {
  tenantId: string;
  organizationId: string;
  integrationId: string;
  integrationName: string;
  microsoftTenantId: string;
  clientId: string;
  clientSecret: string;
}

export interface ResolveMicrosoftGraphArgs {
  organizationId: string;
  action: MicrosoftGraphAction;
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

async function resolveGraphSecret(
  tenantId: string,
  organizationId: string,
  secretName: "tenant_id" | "client_id" | "client_secret",
  args: ResolveMicrosoftGraphArgs,
): Promise<string> {
  try {
    const r = await resolveTenantIntegrationSecretValue({
      tenantId,
      organizationId,
      integrationKind: "microsoft_graph",
      secretName,
      integrationName: "default",
      reason: args.reason,
      functionName: args.functionName,
      requestId: args.requestId,
    });
    return r.value;
  } catch (e) {
    if (e instanceof TenantIntegrationSecretError) {
      const mapped = mapTenantSecretErrorToGraphCode(e.code);
      throw new TenantMicrosoftGraphError(mapped, INTERNAL_MESSAGES[mapped]);
    }
    throw new TenantMicrosoftGraphError(
      "configuration_unavailable",
      INTERNAL_MESSAGES.configuration_unavailable,
    );
  }
}

/**
 * Shared preflight: organization → tenant lookup, environment gate,
 * Microsoft Graph integration lookup. Throws TenantMicrosoftGraphError.
 */
async function resolveTenantGraphIntegrationPreflight(
  args: ResolveMicrosoftGraphArgs,
): Promise<{ tenantId: string; integrationId: string; integrationName: string }> {
  if (!args?.organizationId) {
    throw new TenantMicrosoftGraphError(
      "organization_context_missing",
      INTERNAL_MESSAGES.organization_context_missing,
    );
  }
  if (args.action !== "real_integration") {
    throw new TenantMicrosoftGraphError(
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
    throw new TenantMicrosoftGraphError(orgClass.code, INTERNAL_MESSAGES[orgClass.code]);
  }
  const tenantId = orgClass.tenantId;

  const { error: gateErr } = await supabase.rpc("assert_environment_action_allowed", {
    _organization_id: args.organizationId,
    _action: args.action,
    _reason: args.reason ?? "microsoft-graph-runtime",
  });
  if (gateErr) {
    const gateCode = classifyEnvironmentGateError(gateErr as { code?: string | null });
    throw new TenantMicrosoftGraphError(gateCode, INTERNAL_MESSAGES[gateCode]);
  }

  const { data: integ, error: integErr } = await supabase
    .from("tenant_integrations")
    .select("id, name, is_enabled, status")
    .eq("tenant_id", tenantId)
    .eq("kind", "microsoft_graph")
    .eq("name", "default")
    .maybeSingle();
  const integClass = classifyGraphIntegrationLookup(integErr, integ);
  if (!integClass.ok) {
    throw new TenantMicrosoftGraphError(
      integClass.code,
      INTERNAL_MESSAGES[integClass.code],
    );
  }
  return {
    tenantId,
    integrationId: integClass.integrationId,
    integrationName: (integ?.name as string) ?? "default",
  };
}

export async function resolveTenantMicrosoftGraphRuntimeConfig(
  args: ResolveMicrosoftGraphArgs,
): Promise<MicrosoftGraphRuntimeConfig> {
  const pf = await resolveTenantGraphIntegrationPreflight(args);
  const rawTenantId = await resolveGraphSecret(
    pf.tenantId,
    args.organizationId,
    "tenant_id",
    args,
  );
  const rawClientId = await resolveGraphSecret(
    pf.tenantId,
    args.organizationId,
    "client_id",
    args,
  );
  const clientSecret = await resolveGraphSecret(
    pf.tenantId,
    args.organizationId,
    "client_secret",
    args,
  );

  const microsoftTenantId =
    typeof rawTenantId === "string" ? rawTenantId.trim() : "";
  const clientId = typeof rawClientId === "string" ? rawClientId.trim() : "";
  if (!isValidGuid(microsoftTenantId) || !isValidGuid(clientId)) {
    throw new TenantMicrosoftGraphError(
      "identifier_invalid",
      INTERNAL_MESSAGES.identifier_invalid,
    );
  }
  if (typeof clientSecret !== "string" || clientSecret.length === 0) {
    throw new TenantMicrosoftGraphError(
      "secret_missing",
      INTERNAL_MESSAGES.secret_missing,
    );
  }
  return {
    tenantId: pf.tenantId,
    organizationId: args.organizationId,
    integrationId: pf.integrationId,
    integrationName: pf.integrationName,
    microsoftTenantId,
    clientId,
    clientSecret,
  };
}

// Phase 4D.14A.7D — Public-client identity resolver.
//
// Resolves ONLY the public application identifiers (Microsoft tenant id +
// AAD client id) required by the browser-side Microsoft File Picker. The
// client secret is intentionally never fetched, and no Graph token is
// acquired. Reuses the same organization / gate / integration preflight
// so behavior remains identical to the full runtime resolver until the
// point where secrets diverge.

export interface MicrosoftGraphClientIdentity {
  tenantId: string;
  organizationId: string;
  integrationId: string;
  microsoftTenantId: string;
  clientId: string;
}

export async function resolveTenantMicrosoftGraphClientIdentity(
  args: ResolveMicrosoftGraphArgs,
): Promise<MicrosoftGraphClientIdentity> {
  const pf = await resolveTenantGraphIntegrationPreflight(args);
  const rawTenantId = await resolveGraphSecret(
    pf.tenantId,
    args.organizationId,
    "tenant_id",
    args,
  );
  const rawClientId = await resolveGraphSecret(
    pf.tenantId,
    args.organizationId,
    "client_id",
    args,
  );
  const microsoftTenantId =
    typeof rawTenantId === "string" ? rawTenantId.trim() : "";
  const clientId = typeof rawClientId === "string" ? rawClientId.trim() : "";
  if (!isValidGuid(microsoftTenantId) || !isValidGuid(clientId)) {
    throw new TenantMicrosoftGraphError(
      "identifier_invalid",
      INTERNAL_MESSAGES.identifier_invalid,
    );
  }
  return {
    tenantId: pf.tenantId,
    organizationId: args.organizationId,
    integrationId: pf.integrationId,
    microsoftTenantId,
    clientId,
  };
}

