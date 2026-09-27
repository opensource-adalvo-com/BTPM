// Phase 4D.14A.2 — MuleSoft KPI Tenant runtime resolver (Edge Function-only).
//
// Resolves the effective MuleSoft KPI runtime configuration for a given
// Organization:
//   1. Resolve tenant from the canonical `organizations` row.
//      NEVER trust a caller-supplied tenant id.
//      NEVER derive tenant via `profiles.organization_id`.
//   2. Apply the environment safety gate:
//        - action = "real_integration" for catalog/dimensions reads
//        - action = "external_api_write" for submission/retry paths
//   3. Require the Tenant integration `mulesoft_kpi / default` with
//      `is_enabled=true` AND `status='active'`.
//   4. Resolve `api_url`, `username`, `password` via the service-only Vault
//      value resolver. Fail closed on any missing / blocked / invalid value.
//
// This module NEVER logs or returns:
//   - secret values, Authorization headers
//   - Vault UUIDs, fingerprints, ciphertext
//   - decrypted resolver metadata
//
// It is service-role-only. It must not be imported from browser code.

// deno-lint-ignore-file no-explicit-any
import { createClient } from "npm:@supabase/supabase-js@2";
import {
  resolveTenantIntegrationSecretValue,
  TenantIntegrationSecretError,
} from "./tenantIntegrationSecrets.ts";
import { checkOutboundUrl } from "./outboundRequestGuard.ts";

export type MulesoftKpiAction = "real_integration" | "external_api_write";

export type MulesoftKpiResolveErrorCode =
  | "organization_context_missing"
  | "organization_not_found"
  | "environment_action_blocked"
  | "integration_not_configured"
  | "integration_disabled"
  | "secret_missing"
  | "secret_blocked"
  | "api_url_invalid"
  | "configuration_unavailable";

export class TenantMulesoftKpiError extends Error {
  code: MulesoftKpiResolveErrorCode;
  constructor(code: MulesoftKpiResolveErrorCode, message: string) {
    super(message);
    this.code = code;
    this.name = "TenantMulesoftKpiError";
  }
}

/**
 * Fixed public-safe messages per internal MuleSoft KPI resolver code.
 * Exported for reuse by the runtime resolver so a single source of truth
 * feeds both the safe public error mapper and thrown resolver errors.
 */
export const MULESOFT_KPI_PUBLIC_MESSAGES: Record<
  MulesoftKpiResolveErrorCode,
  string
> = {
  organization_context_missing: "Organization context is unavailable.",
  organization_not_found: "The Organization could not be resolved.",
  environment_action_blocked:
    "MuleSoft KPI access is not allowed in this environment.",
  integration_not_configured:
    "The MuleSoft KPI Tenant integration is not configured.",
  integration_disabled:
    "The MuleSoft KPI Tenant integration is disabled or incomplete.",
  // deepcode ignore HardcodedNonCryptoSecret: <please specify a reason of ignoring this>
  secret_missing: "The MuleSoft KPI Tenant integration is incomplete.",
  // deepcode ignore HardcodedNonCryptoSecret: <please specify a reason of ignoring this>
  secret_blocked:
    "The MuleSoft KPI Tenant integration is disabled for this Organization.",
  api_url_invalid: "The MuleSoft KPI Tenant integration API URL is invalid.",
  configuration_unavailable:
    "The MuleSoft KPI Tenant integration configuration is temporarily unavailable.",
};

/**
 * Pure classifier that maps a generic Tenant integration secret resolver
 * error code to the internal MuleSoft KPI resolver code. Exported for
 * targeted unit testing without a live Vault or Supabase connection.
 *
 *   blocked              → secret_blocked
 *   not_found            → secret_missing
 *   empty                → secret_missing
 *   malformed            → configuration_unavailable
 *   resolver_unavailable → configuration_unavailable
 */
export function mapTenantSecretErrorToMulesoftKpiCode(
  code:
    | "blocked"
    | "not_found"
    | "empty"
    | "malformed"
    | "resolver_unavailable",
): MulesoftKpiResolveErrorCode {
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
 * Canonical safe public-error mapper for MuleSoft KPI runtime configuration
 * failures. Every browser-facing runtime surface (submit / retry / catalog /
 * dimensions) MUST route configuration-resolution catches through this
 * function. The return shape is intentionally minimal — a stable machine
 * code and a fixed generic message — and NEVER contains logical secret
 * names, RPC error text, environment variable names, IDs, fingerprints,
 * ciphertext, or arbitrary original error text.
 */
export function toSafeMulesoftKpiPublicError(error: unknown): {
  code: string;
  message: string;
} {
  const internal: MulesoftKpiResolveErrorCode =
    error instanceof TenantMulesoftKpiError ? error.code : "configuration_unavailable";
  return {
    code: `MULESOFT_KPI_${internal.toUpperCase()}`,
    message: MULESOFT_KPI_PUBLIC_MESSAGES[internal],
  };
}


export interface MulesoftKpiRuntimeConfig {
  tenantId: string;
  organizationId: string;
  integrationId: string;
  integrationName: string;
  apiUrl: string;
  username: string;
  password: string;
}

export interface ResolveMulesoftKpiArgs {
  organizationId: string;
  action: MulesoftKpiAction;
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
 * Validate the tenant-configured API URL before it can become the target of a
 * server-side request.
 *
 * `api_url` is Tenant Admin-controlled, so it is untrusted input to every
 * Edge Function that fetches it. Beyond scheme and embedded credentials, the
 * shared outbound guard rejects loopback, link-local (cloud instance
 * metadata), private, CGNAT, reserved and internal-only hosts — without it
 * this value is an SSRF pivot into infrastructure the caller cannot otherwise
 * reach. Callers must additionally refuse redirects; see
 * `outboundRequestGuard.ts`.
 */
function validateApiUrl(rawUrl: string): string {
  const check = checkOutboundUrl(rawUrl);
  if (!check.ok) {
    throw new TenantMulesoftKpiError(
      "api_url_invalid",
      "The MuleSoft KPI Tenant integration API URL is invalid.",
    );
  }
  return rawUrl;
}

/**
 * Resolve MuleSoft KPI runtime configuration for an Organization.
 * Fail-closed on any missing/blocked/invalid condition.
 * Never falls back to Global environment secrets.
 */
export async function resolveTenantMulesoftKpiRuntimeConfig(
  args: ResolveMulesoftKpiArgs,
): Promise<MulesoftKpiRuntimeConfig> {
  if (!args?.organizationId) {
    throw new TenantMulesoftKpiError(
      "organization_context_missing",
      "Organization context is required to resolve MuleSoft KPI credentials.",
    );
  }
  if (!args.action) {
    throw new TenantMulesoftKpiError(
      "environment_action_blocked",
      "MuleSoft KPI runtime resolver requires an environment action.",
    );
  }

  const supabase = serviceClient();

  // 1. Canonical tenant lookup via organizations row.
  const { data: orgRow, error: orgErr } = await supabase
    .from("organizations")
    .select("id, tenant_id")
    .eq("id", args.organizationId)
    .maybeSingle();
  if (orgErr || !orgRow?.tenant_id) {
    throw new TenantMulesoftKpiError(
      "organization_not_found",
      "Organization not found or missing tenant.",
    );
  }
  const tenantId = orgRow.tenant_id as string;

  // 2. Environment safety gate.
  const { error: gateErr } = await supabase.rpc(
    "assert_environment_action_allowed",
    {
      _organization_id: args.organizationId,
      _action: args.action,
      _reason: args.reason ?? "mulesoft-kpi-runtime",
    },
  );
  if (gateErr) {
    throw new TenantMulesoftKpiError(
      "environment_action_blocked",
      args.action === "external_api_write"
        ? "External API writes are disabled in this environment."
        : "Real integrations are disabled in this environment.",
    );
  }

  // 3. Tenant integration must be mulesoft_kpi / default, enabled + active.
  const { data: integ, error: integErr } = await supabase
    .from("tenant_integrations")
    .select("id, name, is_enabled, status")
    .eq("tenant_id", tenantId)
    .eq("kind", "mulesoft_kpi")
    .eq("name", "default")
    .maybeSingle();
  if (integErr || !integ?.id) {
    throw new TenantMulesoftKpiError(
      "integration_not_configured",
      "The MuleSoft KPI Tenant integration is not configured.",
    );
  }
  if (!integ.is_enabled || integ.status !== "active") {
    throw new TenantMulesoftKpiError(
      "integration_disabled",
      "The MuleSoft KPI Tenant integration is disabled or incomplete.",
    );
  }
  const integrationId = integ.id as string;
  const integrationName = (integ.name as string) ?? "default";

  // 4. Resolve api_url / username / password via Vault (service-only).
  //    Public-facing messages never reference the logical secret name.
  async function readSecret(name: "api_url" | "username" | "password"): Promise<string> {
    try {
      const r = await resolveTenantIntegrationSecretValue({
        tenantId,
        organizationId: args.organizationId,
        integrationKind: "mulesoft_kpi",
        secretName: name,
        integrationName: "default",
        reason: args.reason,
        functionName: args.functionName,
        requestId: args.requestId,
      });
      return r.value;
    } catch (e) {
      if (e instanceof TenantIntegrationSecretError) {
        const mapped = mapTenantSecretErrorToMulesoftKpiCode(e.code);
        throw new TenantMulesoftKpiError(
          mapped,
          MULESOFT_KPI_PUBLIC_MESSAGES[mapped],
        );
      }
      // Unexpected resolver/RPC/network failure — never propagate raw text.
      throw new TenantMulesoftKpiError(
        "configuration_unavailable",
        MULESOFT_KPI_PUBLIC_MESSAGES.configuration_unavailable,
      );
    }

  }

  // Validate WITHOUT trimming password (per spec).
  const apiUrlRaw = (await readSecret("api_url")).trim();
  const username = (await readSecret("username")).trim();
  const password = await readSecret("password");

  if (!apiUrlRaw) {
    throw new TenantMulesoftKpiError(
      "api_url_invalid",
      "The MuleSoft KPI Tenant integration API URL is invalid.",
    );
  }
  if (!username) {
    throw new TenantMulesoftKpiError(
      "secret_missing",
      "The MuleSoft KPI Tenant integration is incomplete.",
    );
  }
  if (password.length === 0) {
    throw new TenantMulesoftKpiError(
      "secret_missing",
      "The MuleSoft KPI Tenant integration is incomplete.",
    );
  }
  const apiUrl = validateApiUrl(apiUrlRaw);

  return {
    tenantId,
    organizationId: args.organizationId,
    integrationId,
    integrationName,
    apiUrl,
    username,
    password,
  };
}
