// BTPM — Wave C2, Step C2.6 (refactored under Phase 4D.14A.2)
// Shared MuleSoft KPI App connector helper.
//
// Responsibilities:
//   - Transport-only: build HTTP Basic Auth header from a caller-supplied
//     username + password, POST a caller-supplied payload as JSON, parse the
//     upstream response, return a normalized result object.
//   - Credentials are resolved by the caller via the Tenant MuleSoft KPI
//     runtime resolver (`_shared/tenantMulesoftKpi.ts`). This module does
//     NOT read `KPI_API_URL`, `KPI_API_USERNAME`, or `KPI_API_PASSWORD` and
//     does NOT touch the database, Vault, tenants, or organizations.
//
// Hard rules:
//   - Never log or return credentials, Authorization header, payload, or
//     the full decrypted upstream body.
//   - Never mutate inputs.

import { checkOutboundUrl } from "./outboundRequestGuard.ts";

export type ConnectorOutcome = "success" | "http_error" | "transport_error";

export interface SafeEndpointSummary {
  host: string | null;
  pathname: string | null;
}

export interface ConnectorResult {
  ok: boolean;
  outcome: ConnectorOutcome;
  elapsed_ms: number;
  status: number | null;
  status_text: string | null;
  body: unknown;             // parsed JSON, raw text, or null
  body_summary: unknown;     // compact, safe-to-persist summary
  error_message: string | null;
  external_correlation_id: string | null;
  /** Host + pathname only — no query, no credential, no header. */
  safe_endpoint_summary: SafeEndpointSummary;
}

function buildBasicAuthHeader(username: string, password: string): string {
  return `Basic ${btoa(`${username}:${password}`)}`;
}


/**
 * Compact, non-sensitive summary of an upstream body for persistence.
 * - For JSON objects: keep top-level scalar fields and shallow shape only.
 * - For arrays: keep length and first-item shape only.
 * - For strings: truncate to 500 chars.
 */
function summarizeBody(body: unknown): unknown {
  if (body === null || body === undefined) return null;
  if (typeof body === "string") {
    return body.length > 500 ? body.slice(0, 500) + "…" : body;
  }
  if (typeof body === "number" || typeof body === "boolean") return body;
  if (Array.isArray(body)) {
    return {
      _type: "array",
      length: body.length,
      first_item_keys:
        body.length > 0 && body[0] && typeof body[0] === "object"
          ? Object.keys(body[0] as Record<string, unknown>).slice(0, 20)
          : null,
    };
  }
  if (typeof body === "object") {
    const obj = body as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    let count = 0;
    for (const k of Object.keys(obj)) {
      if (count >= 20) break;
      const v = obj[k];
      if (v === null || ["string", "number", "boolean"].includes(typeof v)) {
        if (typeof v === "string" && v.length > 200) {
          out[k] = v.slice(0, 200) + "…";
        } else {
          out[k] = v;
        }
      } else if (Array.isArray(v)) {
        out[k] = { _type: "array", length: v.length };
      } else if (typeof v === "object") {
        out[k] = { _type: "object", keys: Object.keys(v as object).slice(0, 10) };
      }
      count++;
    }
    return out;
  }
  return null;
}

function extractCorrelationId(body: unknown): string | null {
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  const o = body as Record<string, unknown>;
  for (const key of [
    "correlation_id",
    "correlationId",
    "x-correlation-id",
    "request_id",
    "requestId",
    "reference",
    "reference_id",
    "referenceId",
  ]) {
    const v = o[key];
    if (typeof v === "string" && v.trim() !== "") return v;
    if (typeof v === "number") return String(v);
  }
  return null;
}

export interface SubmitOptions {
  /** Optional opaque request id for correlation in the connector layer.
   *  This is NOT sent upstream; it's just echoed in the connector result. */
  request_id?: string;
  /** Hard timeout in ms. Defaults to 30_000. */
  timeout_ms?: number;
}

/**
 * Caller-supplied connector configuration. These values are resolved from
 * the MuleSoft KPI Tenant integration (Vault) by
 * `resolveTenantMulesoftKpiRuntimeConfig` and passed in per invocation.
 * They MUST NOT come from Global env secrets.
 */
export interface KpiAppConnectorConfig {
  apiUrl: string;
  username: string;
  password: string;
}

/**
 * Submit an already-built KPI App payload to MuleSoft.
 * The `payload` argument MUST come from the C2.5 shared builder.
 * The `config` argument MUST come from the Tenant runtime resolver.
 */
export async function submitKpiAppPayload(
  payload: unknown,
  config: KpiAppConnectorConfig,
  opts: SubmitOptions = {},
): Promise<ConnectorResult> {
  const apiUrl = config.apiUrl;
  const apiUsername = config.username;
  const apiPassword = config.password;


  // Safe endpoint summary — host + pathname only. No query string, no
  // credential, no header. Used in error responses for diagnostics
  // (e.g. KPI_API_ENDPOINT_NOT_FOUND).
  let safeEndpointSummary: SafeEndpointSummary = { host: null, pathname: null };
  try {
    const u = new URL(apiUrl);
    safeEndpointSummary = { host: u.host, pathname: u.pathname };
  } catch {
    /* ignore — invalid URL will surface as transport_error below */
  }

  const startedAt = Date.now();
  const controller = new AbortController();
  const timeoutMs = opts.timeout_ms ?? 30_000;
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    // `apiUrl` originates from the Tenant Admin-controlled `api_url` secret.
    // The Tenant resolver already vets it (`validateApiUrl`), but this POST
    // carries both the payload and Basic credentials, so the check is repeated
    // at the point of use rather than inherited from a caller's invariant.
    // A rejection surfaces through the catch below as `transport_error`.
    const urlCheck = checkOutboundUrl(apiUrl);
    if (!urlCheck.ok) {
      throw new Error(`Outbound URL is not permitted (${urlCheck.reason}).`);
    }

    // `redirect: "manual"` is what makes the check above hold: a permitted
    // public host answering 302 would otherwise re-aim this request — payload
    // and credentials included — at an internal address.
    const upstream = await fetch(urlCheck.url.toString(), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": buildBasicAuthHeader(apiUsername, apiPassword),
      },
      body: JSON.stringify(payload),
      redirect: "manual",
      signal: controller.signal,
    });

    const elapsed_ms = Date.now() - startedAt;
    const status = upstream.status;
    const status_text = upstream.statusText || null;

    let body: unknown = null;
    try {
      const text = await upstream.text();
      if (text && text.trim() !== "") {
        try {
          body = JSON.parse(text);
        } catch {
          body = text;
        }
      } else {
        body = null;
      }
    } catch {
      body = null;
    }

    const ok = upstream.ok;
    return {
      ok,
      outcome: ok ? "success" : "http_error",
      elapsed_ms,
      status,
      status_text,
      body,
      body_summary: summarizeBody(body),
      error_message: ok ? null : `Upstream HTTP ${status} ${status_text ?? ""}`.trim(),
      external_correlation_id: extractCorrelationId(body),
      safe_endpoint_summary: safeEndpointSummary,
    };
  } catch (e) {
    const elapsed_ms = Date.now() - startedAt;
    const msg = e instanceof Error ? e.message : "Transport error";
    // Do NOT include any auth header / payload content in the error.
    return {
      ok: false,
      outcome: "transport_error",
      elapsed_ms,
      status: null,
      status_text: null,
      body: null,
      body_summary: null,
      error_message: msg.slice(0, 500),
      external_correlation_id: null,
      safe_endpoint_summary: safeEndpointSummary,
    };
  } finally {
    clearTimeout(timer);
  }
}
