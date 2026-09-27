// Phase 4D.14A.8A — Azure OpenAI Tenant runtime resolver (Edge-only).
//
// Resolves the effective Azure OpenAI runtime configuration for an
// Organization. Never returns the API key or endpoint to the browser.
//
// Steps:
//   1. Require organizationId.
//   2. Resolve tenant from `organizations` row (never trusts caller input,
//      never reads `profiles.organization_id`).
//   3. Apply `assert_environment_action_allowed`.
//   4. Require Tenant integration `azure_openai / default` enabled + active.
//   5. Read and validate the `endpoint` from integration `config_metadata`.
//   6. Resolve `api_key` through the canonical Tenant secret-value resolver
//      (honors organization overrides).
//
// Never reads `AZURE_OPENAI_*`, `AI_PROVIDER`, or `AI_EMBEDDING_PROVIDER`.
// Never falls back to OpenAI. Never caches credentials globally. Never
// returns credentials or endpoints to browser code.

// deno-lint-ignore-file no-explicit-any
import { createClient } from "npm:@supabase/supabase-js@2";
import {
  resolveTenantIntegrationSecretValue,
  TenantIntegrationSecretError,
} from "./tenantIntegrationSecrets.ts";
import {
  azureOpenAiV1BaseUrl,
  normalizeAzureOpenAiEndpoint,
} from "./azureOpenAiEndpoint.ts";

export type AzureOpenAiAction = "real_integration" | "external_api_write";

export type AzureOpenAiResolveErrorCode =
  | "organization_context_missing"
  | "organization_not_found"
  | "environment_action_blocked"
  | "integration_not_configured"
  | "integration_disabled"
  | "endpoint_missing"
  | "endpoint_invalid"
  | "secret_missing"
  | "secret_blocked"
  | "configuration_unavailable";

export class TenantAzureOpenAiError extends Error {
  code: AzureOpenAiResolveErrorCode;
  constructor(code: AzureOpenAiResolveErrorCode, message: string) {
    super(message);
    this.code = code;
    this.name = "TenantAzureOpenAiError";
  }
}

const AZURE_INTERNAL_MESSAGES: Record<AzureOpenAiResolveErrorCode, string> = {
  organization_context_missing: "Organization context is unavailable.",
  organization_not_found: "The Organization could not be resolved.",
  environment_action_blocked:
    "Azure OpenAI access is not allowed for this Organization or environment.",
  integration_not_configured:
    "The Azure OpenAI Tenant integration is not configured or is incomplete.",
  integration_disabled:
    "The Azure OpenAI Tenant integration is not configured or is incomplete.",
  endpoint_missing:
    "The Azure OpenAI Tenant integration is not configured or is incomplete.",
  endpoint_invalid:
    "The Azure OpenAI Tenant integration is not configured or is incomplete.",
  // deepcode ignore HardcodedNonCryptoSecret: <please specify a reason of ignoring this>
  secret_missing:
    "The Azure OpenAI Tenant integration is not configured or is incomplete.",
  // deepcode ignore HardcodedNonCryptoSecret: <please specify a reason of ignoring this>
  secret_blocked:
    "Azure OpenAI access is not allowed for this Organization or environment.",
  configuration_unavailable:
    "Azure OpenAI configuration is temporarily unavailable.",
};

/** Pure classifier for Tenant secret resolver errors → Azure resolver codes. */
export function mapTenantSecretErrorToAzureCode(
  code: "blocked" | "not_found" | "empty" | "malformed" | "resolver_unavailable",
): AzureOpenAiResolveErrorCode {
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

export function classifyAzureEnvironmentGateError(
  err: { code?: string | null } | null | undefined,
): AzureOpenAiResolveErrorCode {
  const code = err?.code ?? null;
  if (code === "42501") return "environment_action_blocked";
  return "configuration_unavailable";
}

export function classifyAzureOrganizationLookup(
  err: unknown,
  row: { tenant_id?: string | null } | null | undefined,
):
  | { ok: true; tenantId: string }
  | { ok: false; code: AzureOpenAiResolveErrorCode } {
  if (err) return { ok: false, code: "configuration_unavailable" };
  const tenantId = row?.tenant_id ?? null;
  if (!tenantId) return { ok: false, code: "organization_not_found" };
  return { ok: true, tenantId };
}

export function classifyAzureIntegrationLookup(
  err: unknown,
  row:
    | {
      id?: string | null;
      is_enabled?: boolean | null;
      status?: string | null;
      config_metadata?: Record<string, unknown> | null;
    }
    | null
    | undefined,
):
  | {
    ok: true;
    integrationId: string;
    configMetadata: Record<string, unknown> | null;
  }
  | { ok: false; code: AzureOpenAiResolveErrorCode } {
  if (err) return { ok: false, code: "configuration_unavailable" };
  if (!row?.id) return { ok: false, code: "integration_not_configured" };
  if (!row.is_enabled || row.status !== "active") {
    return { ok: false, code: "integration_disabled" };
  }
  return {
    ok: true,
    integrationId: row.id,
    configMetadata: (row.config_metadata as Record<string, unknown> | null) ?? null,
  };
}

/**
 * Extract and validate the Azure endpoint from integration metadata.
 * Distinguishes missing vs invalid so the caller can classify accurately.
 */
export function classifyAzureEndpointFromMetadata(
  configMetadata: Record<string, unknown> | null,
):
  | { ok: true; endpoint: string; baseUrl: string }
  | { ok: false; code: AzureOpenAiResolveErrorCode } {
  const raw = configMetadata?.["endpoint"];
  if (raw === undefined || raw === null || raw === "") {
    return { ok: false, code: "endpoint_missing" };
  }
  const endpoint = normalizeAzureOpenAiEndpoint(raw);
  if (!endpoint) return { ok: false, code: "endpoint_invalid" };
  return { ok: true, endpoint, baseUrl: azureOpenAiV1BaseUrl(endpoint) };
}

export function toSafeAzureOpenAiPublicError(error: unknown): {
  error: string;
  note: string;
} {
  const internal: AzureOpenAiResolveErrorCode =
    error instanceof TenantAzureOpenAiError
      ? error.code
      : "configuration_unavailable";
  switch (internal) {
    case "environment_action_blocked":
    case "secret_blocked":
      return {
        error: "azure_openai_access_blocked",
        note:
          "Azure OpenAI access is not allowed for this Organization or environment.",
      };
    case "configuration_unavailable":
    case "organization_context_missing":
    case "organization_not_found":
      return {
        error: "azure_openai_configuration_unavailable",
        note: "Azure OpenAI configuration is temporarily unavailable.",
      };
    case "integration_not_configured":
    case "integration_disabled":
    case "endpoint_missing":
    case "endpoint_invalid":
    case "secret_missing":
    default:
      return {
        error: "azure_openai_not_configured",
        note:
          "The Azure OpenAI Tenant integration is not configured or is incomplete.",
      };
  }
}

export interface AzureOpenAiRuntimeConfig {
  tenantId: string;
  organizationId: string;
  integrationId: string;
  integrationName: string;
  endpoint: string;
  baseUrl: string;
  apiKey: string;
}

export interface ResolveAzureArgs {
  organizationId: string;
  action: AzureOpenAiAction;
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

export async function resolveTenantAzureOpenAiRuntimeConfig(
  args: ResolveAzureArgs,
): Promise<AzureOpenAiRuntimeConfig> {
  if (!args?.organizationId) {
    throw new TenantAzureOpenAiError(
      "organization_context_missing",
      AZURE_INTERNAL_MESSAGES.organization_context_missing,
    );
  }
  if (!args.action) {
    throw new TenantAzureOpenAiError(
      "environment_action_blocked",
      AZURE_INTERNAL_MESSAGES.environment_action_blocked,
    );
  }

  const supabase = serviceClient();

  // 1. Canonical tenant via organizations row.
  const { data: orgRow, error: orgErr } = await supabase
    .from("organizations")
    .select("id, tenant_id")
    .eq("id", args.organizationId)
    .maybeSingle();
  const orgClass = classifyAzureOrganizationLookup(orgErr, orgRow);
  if (!orgClass.ok) {
    throw new TenantAzureOpenAiError(
      orgClass.code,
      AZURE_INTERNAL_MESSAGES[orgClass.code],
    );
  }
  const tenantId = orgClass.tenantId;

  // 2. Environment safety gate.
  const { error: gateErr } = await supabase.rpc(
    "assert_environment_action_allowed",
    {
      _organization_id: args.organizationId,
      _action: args.action,
      _reason: args.reason ?? "azure-openai-runtime",
    },
  );
  if (gateErr) {
    const c = classifyAzureEnvironmentGateError(
      gateErr as { code?: string | null },
    );
    throw new TenantAzureOpenAiError(c, AZURE_INTERNAL_MESSAGES[c]);
  }

  // 3. Tenant integration must be azure_openai/default, enabled+active.
  const { data: integ, error: integErr } = await supabase
    .from("tenant_integrations")
    .select("id, name, is_enabled, status, config_metadata")
    .eq("tenant_id", tenantId)
    .eq("kind", "azure_openai")
    .eq("name", "default")
    .maybeSingle();
  const integClass = classifyAzureIntegrationLookup(integErr, integ);
  if (!integClass.ok) {
    throw new TenantAzureOpenAiError(
      integClass.code,
      AZURE_INTERNAL_MESSAGES[integClass.code],
    );
  }

  // 4. Endpoint from config_metadata.
  const epClass = classifyAzureEndpointFromMetadata(integClass.configMetadata);
  if (!epClass.ok) {
    throw new TenantAzureOpenAiError(
      epClass.code,
      AZURE_INTERNAL_MESSAGES[epClass.code],
    );
  }

  // 5. api_key via Vault (service-only, honors org override).
  let apiKey: string;
  try {
    const r = await resolveTenantIntegrationSecretValue({
      tenantId,
      organizationId: args.organizationId,
      integrationKind: "azure_openai",
      secretName: "api_key",
      integrationName: "default",
      reason: args.reason,
      functionName: args.functionName,
      requestId: args.requestId,
    });
    apiKey = r.value;
  } catch (e) {
    if (e instanceof TenantIntegrationSecretError) {
      const mapped = mapTenantSecretErrorToAzureCode(e.code);
      throw new TenantAzureOpenAiError(
        mapped,
        AZURE_INTERNAL_MESSAGES[mapped],
      );
    }
    throw new TenantAzureOpenAiError(
      "configuration_unavailable",
      AZURE_INTERNAL_MESSAGES.configuration_unavailable,
    );
  }

  if (typeof apiKey !== "string" || apiKey.length === 0) {
    throw new TenantAzureOpenAiError(
      "secret_missing",
      AZURE_INTERNAL_MESSAGES.secret_missing,
    );
  }

  return {
    tenantId,
    organizationId: args.organizationId,
    integrationId: integClass.integrationId,
    integrationName: (integ?.name as string) ?? "default",
    endpoint: epClass.endpoint,
    baseUrl: epClass.baseUrl,
    apiKey,
  };
}
