// Phase 4D.14A.3B — OpenAI Tenant runtime resolver (Edge Function-only).
//
// Resolves the effective OpenAI API key for a given Organization:
//   1. Resolve tenant from the canonical `organizations` row.
//      NEVER trust a caller-supplied tenant id.
//      NEVER derive tenant via `profiles.organization_id`.
//   2. Apply the environment safety gate:
//        - action = "real_integration" for OpenAI GET/polling requests
//        - action = "external_api_write" for OpenAI POST/generation requests
//   3. Require the Tenant integration `openai / default` with
//      `is_enabled=true` AND `status='active'`.
//   4. Resolve `api_key` via the service-only Vault value resolver.
//      Fail closed on any missing / blocked / invalid value.
//
// This module NEVER logs or returns:
//   - the API key, Authorization headers
//   - Vault UUIDs, fingerprints, ciphertext
//   - decrypted resolver metadata
//   - Tenant/Organization IDs in public errors
//
// It is service-role-only. It must not be imported from browser code.

// deno-lint-ignore-file no-explicit-any
import { createClient } from "npm:@supabase/supabase-js@2";
import {
  resolveTenantIntegrationSecretValue,
  TenantIntegrationSecretError,
} from "./tenantIntegrationSecrets.ts";

export type OpenAiAction = "real_integration" | "external_api_write";

export type OpenAiResolveErrorCode =
  | "organization_context_missing"
  | "organization_not_found"
  | "environment_action_blocked"
  | "integration_not_configured"
  | "integration_disabled"
  | "secret_missing"
  | "secret_blocked"
  | "configuration_unavailable";

export class TenantOpenAiError extends Error {
  code: OpenAiResolveErrorCode;
  constructor(code: OpenAiResolveErrorCode, message: string) {
    super(message);
    this.code = code;
    this.name = "TenantOpenAiError";
  }
}

/**
 * Fixed public-safe messages per internal OpenAI resolver code.
 * The public mapper collapses these to three stable browser contracts.
 */
const OPENAI_INTERNAL_MESSAGES: Record<OpenAiResolveErrorCode, string> = {
  organization_context_missing: "Organization context is unavailable.",
  organization_not_found: "The Organization could not be resolved.",
  environment_action_blocked:
    "OpenAI access is not allowed for this Organization or environment.",
  integration_not_configured:
    "The OpenAI Tenant integration is not configured or is incomplete.",
  integration_disabled:
    "The OpenAI Tenant integration is not configured or is incomplete.",
  // deepcode ignore HardcodedNonCryptoSecret: <please specify a reason of ignoring this>
  secret_missing:
    "The OpenAI Tenant integration is not configured or is incomplete.",
  // deepcode ignore HardcodedNonCryptoSecret: <please specify a reason of ignoring this>
  secret_blocked:
    "OpenAI access is not allowed for this Organization or environment.",
  configuration_unavailable:
    "OpenAI configuration is temporarily unavailable.",
};

/** Pure classifier for Tenant secret resolver errors → OpenAI resolver codes. */
export function mapTenantSecretErrorToOpenAiCode(
  code: "blocked" | "not_found" | "empty" | "malformed" | "resolver_unavailable",
): OpenAiResolveErrorCode {
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

/**
 * Pure classifier for `assert_environment_action_allowed` RPC failures.
 * Only Postgres `insufficient_privilege` (SQLSTATE 42501) represents a
 * deliberate policy/authority rejection. Everything else — network,
 * transport, RPC, RLS misconfiguration, unexpected shape — is
 * infrastructure and must map to `configuration_unavailable`, never to
 * a blocked-access signal.
 *
 * The raw error is never inspected for message text. Only the
 * PostgREST/Supabase `code` field is consulted.
 */
export function classifyEnvironmentGateError(
  err: { code?: string | null } | null | undefined,
): OpenAiResolveErrorCode {
  const code = err?.code ?? null;
  if (code === "42501") return "environment_action_blocked";
  return "configuration_unavailable";
}

/**
 * Pure classifier for the `organizations` lookup. Splits actual query
 * errors (infrastructure) from a legitimate "no such Organization / no
 * tenant_id" result.
 */
export function classifyOrganizationLookup(
  err: unknown,
  row: { tenant_id?: string | null } | null | undefined,
): { ok: true; tenantId: string } | { ok: false; code: OpenAiResolveErrorCode } {
  if (err) return { ok: false, code: "configuration_unavailable" };
  const tenantId = row?.tenant_id ?? null;
  if (!tenantId) return { ok: false, code: "organization_not_found" };
  return { ok: true, tenantId };
}

/**
 * Pure classifier for the `tenant_integrations` lookup for
 * `openai / default`. Splits actual query errors (infrastructure) from
 * an absent row, and preserves the disabled/non-active distinction.
 */
export function classifyOpenAiIntegrationLookup(
  err: unknown,
  row: { id?: string | null; is_enabled?: boolean | null; status?: string | null } | null | undefined,
):
  | { ok: true; integrationId: string }
  | { ok: false; code: OpenAiResolveErrorCode } {
  if (err) return { ok: false, code: "configuration_unavailable" };
  if (!row?.id) return { ok: false, code: "integration_not_configured" };
  if (!row.is_enabled || row.status !== "active") {
    return { ok: false, code: "integration_disabled" };
  }
  return { ok: true, integrationId: row.id };
}

/**
 * Canonical safe public-error mapper for OpenAI runtime configuration
 * failures. Collapses all internal codes to three stable browser contracts:
 *   - openai_not_configured
 *   - openai_access_blocked
 *   - openai_configuration_unavailable
 *
 * Never contains secret material, IDs, RPC text, Vault metadata,
 * fingerprints, or raw resolver output.
 */
export function toSafeOpenAiPublicError(error: unknown): {
  error: string;
  note: string;
} {
  const internal: OpenAiResolveErrorCode =
    error instanceof TenantOpenAiError ? error.code : "configuration_unavailable";
  switch (internal) {
    case "environment_action_blocked":
    case "secret_blocked":
      return {
        error: "openai_access_blocked",
        note: "OpenAI access is not allowed for this Organization or environment.",
      };
    case "configuration_unavailable":
    case "organization_context_missing":
    case "organization_not_found":
      return {
        error: "openai_configuration_unavailable",
        note: "OpenAI configuration is temporarily unavailable.",
      };
    case "integration_not_configured":
    case "integration_disabled":
    case "secret_missing":
    default:
      return {
        error: "openai_not_configured",
        note: "The OpenAI Tenant integration is not configured or is incomplete.",
      };
  }
}

export interface OpenAiRuntimeConfig {
  tenantId: string;
  organizationId: string;
  integrationId: string;
  integrationName: string;
  apiKey: string;
}

export interface ResolveOpenAiArgs {
  organizationId: string;
  action: OpenAiAction;
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

/**
 * Resolve OpenAI runtime configuration for an Organization.
 * Fail-closed on any missing/blocked/invalid condition.
 * Never falls back to Global environment secrets.
 */
export async function resolveTenantOpenAiRuntimeConfig(
  args: ResolveOpenAiArgs,
): Promise<OpenAiRuntimeConfig> {
  if (!args?.organizationId) {
    throw new TenantOpenAiError(
      "organization_context_missing",
      OPENAI_INTERNAL_MESSAGES.organization_context_missing,
    );
  }
  if (!args.action) {
    throw new TenantOpenAiError(
      "environment_action_blocked",
      OPENAI_INTERNAL_MESSAGES.environment_action_blocked,
    );
  }

  const supabase = serviceClient();

  // 1. Canonical tenant lookup via organizations row. Distinguish an
  //    infrastructure error from a legitimate "no such Organization"
  //    outcome so we do not falsely surface "not found" during a
  //    database/PostgREST outage.
  const { data: orgRow, error: orgErr } = await supabase
    .from("organizations")
    .select("id, tenant_id")
    .eq("id", args.organizationId)
    .maybeSingle();
  const orgClass = classifyOrganizationLookup(orgErr, orgRow);
  if (!orgClass.ok) {
    throw new TenantOpenAiError(
      orgClass.code,
      OPENAI_INTERNAL_MESSAGES[orgClass.code],
    );
  }
  const tenantId = orgClass.tenantId;

  // 2. Environment safety gate. Only a genuine policy rejection
  //    (SQLSTATE 42501 / insufficient_privilege) is a block; any other
  //    RPC / transport / RLS misconfiguration failure is infrastructure
  //    and must surface as `configuration_unavailable`.
  const { error: gateErr } = await supabase.rpc(
    "assert_environment_action_allowed",
    {
      _organization_id: args.organizationId,
      _action: args.action,
      _reason: args.reason ?? "openai-runtime",
    },
  );
  if (gateErr) {
    const gateCode = classifyEnvironmentGateError(
      gateErr as { code?: string | null },
    );
    throw new TenantOpenAiError(gateCode, OPENAI_INTERNAL_MESSAGES[gateCode]);
  }

  // 3. Tenant integration must be openai / default, enabled + active.
  //    Split infrastructure errors from an absent row; preserve the
  //    disabled/non-active outcome.
  const { data: integ, error: integErr } = await supabase
    .from("tenant_integrations")
    .select("id, name, is_enabled, status")
    .eq("tenant_id", tenantId)
    .eq("kind", "openai")
    .eq("name", "default")
    .maybeSingle();
  const integClass = classifyOpenAiIntegrationLookup(integErr, integ);
  if (!integClass.ok) {
    throw new TenantOpenAiError(
      integClass.code,
      OPENAI_INTERNAL_MESSAGES[integClass.code],
    );
  }
  const integrationId = integClass.integrationId;
  const integrationName = (integ?.name as string) ?? "default";


  // 4. Resolve api_key via Vault (service-only).
  let apiKey: string;
  try {
    const r = await resolveTenantIntegrationSecretValue({
      tenantId,
      organizationId: args.organizationId,
      integrationKind: "openai",
      secretName: "api_key",
      integrationName: "default",
      reason: args.reason,
      functionName: args.functionName,
      requestId: args.requestId,
    });
    apiKey = r.value;
  } catch (e) {
    if (e instanceof TenantIntegrationSecretError) {
      const mapped = mapTenantSecretErrorToOpenAiCode(e.code);
      throw new TenantOpenAiError(mapped, OPENAI_INTERNAL_MESSAGES[mapped]);
    }
    throw new TenantOpenAiError(
      "configuration_unavailable",
      OPENAI_INTERNAL_MESSAGES.configuration_unavailable,
    );
  }

  if (typeof apiKey !== "string" || apiKey.length === 0) {
    throw new TenantOpenAiError(
      "secret_missing",
      OPENAI_INTERNAL_MESSAGES.secret_missing,
    );
  }

  return {
    tenantId,
    organizationId: args.organizationId,
    integrationId,
    integrationName,
    apiKey,
  };
}
