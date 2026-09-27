// Phase 4D.14A.8C.2A — Canonical Tenant AI chat-completions transport.
//
// Transport-only helper that issues a POST /chat/completions against either
// OpenAI or Azure OpenAI using a resolved `TenantAiTextRuntime`.
//
// This helper:
//   - never resolves Tenant settings
//   - never queries Supabase or Vault
//   - never reads Global env provider settings
//   - never chooses or falls back between providers
//   - never applies model-specific token/temperature rules
//   - never logs or returns API keys, Authorization headers, endpoints,
//     deployment names, prompts, payloads, or raw provider bodies
//
// It is intentionally NOT imported by any production Edge Function in this
// step. 4D.14A.8C.2A only establishes the transport contract.

import type { TenantAiTextRuntime } from "./tenantAiTextRuntime.ts";
import { checkOutboundUrl } from "./outboundRequestGuard.ts";

export type TenantAiChatCompletionFailureCategory =
  | "endpoint_blocked"
  | "credential_rejected"
  | "permission_denied"
  | "request_rejected"
  | "endpoint_not_found"
  | "rate_limited"
  | "timeout"
  | "network_error"
  | "service_unavailable"
  | "response_invalid";

export type TenantAiChatCompletionResult =
  | {
    ok: true;
    httpStatus: number;
    json: Record<string, unknown>;
  }
  | {
    ok: false;
    httpStatus: number | null;
    category: TenantAiChatCompletionFailureCategory;
  };

export interface PostTenantAiChatCompletionArgs {
  runtime: TenantAiTextRuntime;
  /** Chat completions body EXCLUDING provider credentials AND `model`. */
  payload: Record<string, unknown>;
  /** Bounded timeout in ms. Defaults to 30000. Clamped to [1000, 120000]. */
  timeoutMs?: number;
  /** Correlation id used only in structured log lines (never with secrets). */
  requestId?: string;
  /** Fixed operation label used only in structured log lines. */
  operation?: string;
  /** Injected fetch for tests. Must not be exposed to production callers. */
  fetchImpl?: typeof fetch;
}

/** Pure classifier for provider HTTP status codes. */
export function classifyChatCompletionsHttpStatus(
  status: number,
): TenantAiChatCompletionFailureCategory {
  // Redirects are refused rather than followed (see `redirect: "manual"`
  // below), so a 3xx reaches this classifier as a failure. It is reported as
  // `endpoint_blocked`, not as a generic upstream error: the provider tried to
  // re-aim a credentialed request at an address this transport never vetted.
  if (status >= 300 && status < 400) return "endpoint_blocked";
  if (status === 401) return "credential_rejected";
  if (status === 403) return "permission_denied";
  if (status === 404) return "endpoint_not_found";
  if (status === 429) return "rate_limited";
  if (status >= 500) return "service_unavailable";
  if (status >= 400) return "request_rejected";
  return "service_unavailable";
}

/** Pure classifier for transport (throw) failures. */
export function classifyChatCompletionsTransportFailure(
  err: unknown,
): TenantAiChatCompletionFailureCategory {
  const name = (err as { name?: string } | null)?.name;
  if (name === "AbortError" || name === "TimeoutError") return "timeout";
  return "network_error";
}

async function drainDiscard(res: Response): Promise<void> {
  try {
    await res.text();
  } catch {
    /* ignore */
  }
}

function buildAuthHeaders(runtime: TenantAiTextRuntime): HeadersInit {
  const base: Record<string, string> = { "Content-Type": "application/json" };
  if (runtime.authMode === "bearer") {
    base["Authorization"] = `Bearer ${runtime.apiKey}`;
  } else {
    base["api-key"] = runtime.apiKey;
  }
  return base;
}

function clampTimeout(ms: number | undefined): number {
  const raw = typeof ms === "number" && Number.isFinite(ms) ? ms : 30000;
  return Math.max(1000, Math.min(120000, raw));
}

/**
 * POST a chat-completions request against the runtime's provider.
 *
 * The `payload.model` field is ALWAYS overwritten with `runtime.providerModel`
 * so callers cannot inject a different model at the transport layer.
 */
export async function postTenantAiChatCompletion(
  args: PostTenantAiChatCompletionArgs,
): Promise<TenantAiChatCompletionResult> {
  const { runtime, payload } = args;
  const timeoutMs = clampTimeout(args.timeoutMs);
  const operation = args.operation ?? "tenant_ai_chat_completions";
  const reqId = args.requestId ?? "-";
  const doFetch = args.fetchImpl ?? fetch;

  // `runtime.baseUrl` derives from Tenant Admin-controlled integration
  // metadata (the Azure OpenAI `endpoint`), so it is untrusted input to this
  // request. Vet it here, at the point of use, rather than inheriting a
  // caller's invariant: this POST carries the tenant's provider API key.
  const urlCheck = checkOutboundUrl(`${runtime.baseUrl}/chat/completions`);
  if (!urlCheck.ok) {
    console.error(
      `[tenant-ai-chat] endpoint_blocked op=${operation} provider=${runtime.provider} req=${reqId} reason=${urlCheck.reason}`,
    );
    return { ok: false, httpStatus: null, category: "endpoint_blocked" };
  }
  const url = urlCheck.url.toString();
  const body = { ...payload, model: runtime.providerModel };
  const headers = buildAuthHeaders(runtime);

  let response: Response;
  try {
    // `redirect: "manual"` is what makes the check above hold. Without it a
    // permitted public host answering `302 Location: http://169.254.169.254/`
    // would walk the credentialed request straight past the guard.
    response = await doFetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (err) {
    const category = classifyChatCompletionsTransportFailure(err);
    console.error(
      `[tenant-ai-chat] transport_failed op=${operation} provider=${runtime.provider} req=${reqId} category=${category}`,
    );
    return { ok: false, httpStatus: null, category };
  }

  if (!response.ok) {
    const category = classifyChatCompletionsHttpStatus(response.status);
    await drainDiscard(response);
    console.error(
      `[tenant-ai-chat] http_error op=${operation} provider=${runtime.provider} status=${response.status} req=${reqId} category=${category}`,
    );
    return { ok: false, httpStatus: response.status, category };
  }

  let parsed: unknown;
  try {
    parsed = await response.json();
  } catch {
    console.error(
      `[tenant-ai-chat] response_invalid op=${operation} provider=${runtime.provider} status=${response.status} req=${reqId} category=response_invalid`,
    );
    return {
      ok: false,
      httpStatus: response.status,
      category: "response_invalid",
    };
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return {
      ok: false,
      httpStatus: response.status,
      category: "response_invalid",
    };
  }
  return {
    ok: true,
    httpStatus: response.status,
    json: parsed as Record<string, unknown>,
  };
}
