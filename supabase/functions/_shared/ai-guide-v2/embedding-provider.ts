// AI-GUIDE.V2.1C — Embedding provider transport.
// Phase 4D.14A.8C.3 — Unified Tenant AI transport for both OpenAI and
// Azure OpenAI. The runtime is resolved by
// `resolveGuideEmbeddingProviderRuntime` and passed in explicitly. This
// module never reads env vars, never queries Supabase or Vault, never
// selects a provider, and never composes provider-specific URLs beyond
// `${runtime.baseUrl}/embeddings`.
//
// Responsibilities:
//   - validate input batch size and dimensions
//   - POST a single common embedding request body against the runtime
//   - authenticate via bearer (OpenAI) or api-key (Azure OpenAI) based
//     on `runtime.authMode`
//   - normalize the response and validate 1536-dim vectors
//
// It never logs or returns API keys, Authorization headers, endpoints,
// deployment names, provider model IDs, request texts, vectors, or raw
// provider response bodies. Only the canonical BTPM model id is ever
// surfaced.

import type { GuideEmbeddingProviderRuntimeConfig } from "../guideEmbeddingProviderRuntime.ts";
import { checkOutboundUrl } from "../outboundRequestGuard.ts";

export type GuideV2EmbeddingProvider = "openai" | "azure_openai";

export interface EmbedGuideV2Input {
  texts: string[];
  modelLabel: string;
  dimensions: 1536;
  requestId: string;
  runtime: GuideEmbeddingProviderRuntimeConfig;
}

export interface EmbedGuideV2Result {
  ok: boolean;
  embeddings?: number[][];
  provider: GuideV2EmbeddingProvider;
  /** Canonical BTPM model id only. Never the Azure deployment name. */
  model: string;
  dimensions: number;
  error?: { code: string; message: string };
}

const MAX_BATCH = 128;

function fail(
  provider: GuideV2EmbeddingProvider,
  model: string,
  dimensions: number,
  code: string,
  message: string,
): EmbedGuideV2Result {
  return { ok: false, provider, model, dimensions, error: { code, message } };
}

async function drainDiscard(resp: Response): Promise<void> {
  try {
    await resp.text();
  } catch { /* ignore */ }
}

export async function embedGuideV2Texts(
  input: EmbedGuideV2Input,
): Promise<EmbedGuideV2Result> {
  const runtime = input.runtime;
  if (
    !runtime ||
    (runtime.provider !== "openai" && runtime.provider !== "azure_openai")
  ) {
    return fail("openai", "n/a", 1536, "runtime_missing", "embedding runtime not provided");
  }
  const provider: GuideV2EmbeddingProvider = runtime.provider;
  const canonicalModel = runtime.canonicalModel;

  if (runtime.dimensions !== 1536 || input.dimensions !== 1536) {
    return fail(provider, canonicalModel, runtime.dimensions, "dimension_mismatch", "embedding dimensions must be 1536");
  }
  if (!Array.isArray(input.texts) || input.texts.length === 0) {
    return fail(provider, canonicalModel, 1536, "empty_input", "no texts to embed");
  }
  if (input.texts.length > MAX_BATCH) {
    return fail(provider, canonicalModel, 1536, "batch_too_large", "max 128 texts per call");
  }

  // `runtime.baseUrl` derives from Tenant Admin-controlled integration
  // metadata (the Azure OpenAI `endpoint`), so it is untrusted input to this
  // request, which carries the tenant's provider API key. Vet it before the
  // POST; the rejection reason is never surfaced to the browser.
  const urlCheck = checkOutboundUrl(`${runtime.baseUrl}/embeddings`);
  if (!urlCheck.ok) {
    console.warn("guide-v2.embed.endpoint_blocked", {
      request_id: input.requestId,
      provider,
      canonical_model: canonicalModel,
      error_code: "endpoint_blocked",
      reason: urlCheck.reason,
    });
    return fail(provider, canonicalModel, 1536, "endpoint_blocked", "embedding provider endpoint is not permitted");
  }
  const url = urlCheck.url.toString();
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (runtime.authMode === "bearer") {
    headers["authorization"] = `Bearer ${runtime.apiKey}`;
  } else {
    headers["api-key"] = runtime.apiKey;
  }
  const body = {
    model: runtime.providerModel,
    input: input.texts,
    dimensions: 1536,
  };

  const t0 = Date.now();
  let resp: Response;
  try {
    // `redirect: "manual"` is what makes the check above hold. Without it a
    // permitted public host answering `302 Location: http://169.254.169.254/`
    // would walk the credentialed request straight past the guard.
    resp = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      redirect: "manual",
    });
  } catch {
    console.warn("guide-v2.embed.network_error", {
      request_id: input.requestId,
      provider,
      canonical_model: canonicalModel,
      elapsed_ms: Date.now() - t0,
      error_code: "network_error",
    });
    return fail(provider, canonicalModel, 1536, "network_error", "embedding provider network error");
  }

  if (!resp.ok) {
    const code = resp.status >= 300 && resp.status < 400
      ? "endpoint_blocked" // redirect refused, not followed
      : resp.status === 401 || resp.status === 403
      ? "auth_failed"
      : resp.status === 429
        ? "rate_limited"
        : resp.status >= 500
          ? "provider_error"
          : "bad_request";
    console.warn("guide-v2.embed.http_error", {
      request_id: input.requestId,
      provider,
      canonical_model: canonicalModel,
      http_status: resp.status,
      elapsed_ms: Date.now() - t0,
      error_code: code,
    });
    await drainDiscard(resp);
    return fail(provider, canonicalModel, 1536, code, "embedding provider returned an error status");
  }

  let parsed: { data?: Array<{ embedding: number[]; index: number }> };
  try {
    parsed = await resp.json();
  } catch {
    return fail(provider, canonicalModel, 1536, "invalid_response", "embedding provider returned an invalid response");
  }
  if (!parsed.data || parsed.data.length !== input.texts.length) {
    return fail(provider, canonicalModel, 1536, "response_count_mismatch", "embedding provider returned wrong number of vectors");
  }

  const sorted = [...parsed.data].sort((a, b) => a.index - b.index);
  const embeddings: number[][] = sorted.map((d) => d.embedding);
  for (const v of embeddings) {
    if (!Array.isArray(v) || v.length !== 1536) {
      return fail(provider, canonicalModel, 1536, "dimension_mismatch", "embedding provider returned unexpected vector dimensions");
    }
  }

  console.info("guide-v2.embed.ok", {
    request_id: input.requestId,
    provider,
    canonical_model: canonicalModel,
    count: embeddings.length,
    elapsed_ms: Date.now() - t0,
  });

  return { ok: true, embeddings, provider, model: canonicalModel, dimensions: 1536 };
}
