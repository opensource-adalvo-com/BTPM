// Tests for the SSRF guards on the two Tenant AI transports reachable from
// the Guide V2 chat runtime: chat completions and embeddings.
//
// Both build their URL from `runtime.baseUrl`, which derives from Tenant
// Admin-controlled integration metadata. The guard must reject an internal
// target before the credentialed request leaves, and must refuse to follow a
// redirect that would re-aim a permitted host at one.

import {
  assert,
  assertEquals,
} from "https://deno.land/std@0.224.0/assert/mod.ts";

import { postTenantAiChatCompletion } from "../tenantAiChatCompletionsClient.ts";
import { embedGuideV2Texts } from "../ai-guide-v2/embedding-provider.ts";
import type { TenantAiTextRuntime } from "../tenantAiTextRuntime.ts";
import type { GuideEmbeddingProviderRuntimeConfig } from "../guideEmbeddingProviderRuntime.ts";

function textRuntime(baseUrl: string): TenantAiTextRuntime {
  return {
    provider: "azure_openai",
    canonicalModel: "btpm-text",
    providerModel: "deployment-x",
    baseUrl,
    apiKey: "test-key",
    authMode: "api_key",
  };
}

function embeddingRuntime(baseUrl: string): GuideEmbeddingProviderRuntimeConfig {
  return { ...textRuntime(baseUrl), canonicalModel: "btpm-embed", dimensions: 1536 };
}

/** A fetch that fails the test if it is ever called. */
function forbiddenFetch(): typeof fetch {
  return (() => {
    throw new Error("outbound request must not be attempted");
  }) as unknown as typeof fetch;
}

const BLOCKED_BASE_URLS = [
  "http://169.254.169.254/v1", // cloud instance metadata
  "http://127.0.0.1:8080/v1", // loopback
  "http://[::1]/v1", // loopback, IPv6
  "http://10.0.0.5/v1", // RFC1918
  "http://kpi-gateway/v1", // single-label internal name
  "http://vault.internal/v1", // internal-only suffix
  "file:///etc/passwd", // unsupported scheme
  "https://user:pw@api.example.com/v1", // embedded credentials
];

Deno.test("chat completions refuses an internal baseUrl before requesting", async () => {
  for (const baseUrl of BLOCKED_BASE_URLS) {
    const result = await postTenantAiChatCompletion({
      runtime: textRuntime(baseUrl),
      payload: { messages: [] },
      fetchImpl: forbiddenFetch(),
    });
    assert(!result.ok, `${baseUrl} must not be requested`);
    assertEquals(result.category, "endpoint_blocked");
    assertEquals(result.httpStatus, null);
  }
});

Deno.test("chat completions still reaches a permitted public endpoint", async () => {
  let seen: { url: string; redirect?: RequestRedirect } | null = null;
  const result = await postTenantAiChatCompletion({
    runtime: textRuntime("https://api.example.com/v1"),
    payload: { messages: [] },
    fetchImpl: ((url: string, init: RequestInit) => {
      seen = { url, redirect: init.redirect };
      return Promise.resolve(new Response(JSON.stringify({ choices: [] }), { status: 200 }));
    }) as unknown as typeof fetch,
  });
  assert(result.ok);
  assertEquals(seen!.url, "https://api.example.com/v1/chat/completions");
  // Without this, a 302 would walk the credentialed request past the guard.
  assertEquals(seen!.redirect, "manual");
});

Deno.test("chat completions reports a refused redirect as endpoint_blocked", async () => {
  const result = await postTenantAiChatCompletion({
    runtime: textRuntime("https://api.example.com/v1"),
    payload: { messages: [] },
    fetchImpl: (() =>
      Promise.resolve(
        new Response(null, {
          status: 302,
          headers: { Location: "http://169.254.169.254/latest/meta-data/" },
        }),
      )) as unknown as typeof fetch,
  });
  assert(!result.ok);
  assertEquals(result.category, "endpoint_blocked");
});

Deno.test("embeddings refuse an internal baseUrl before requesting", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = forbiddenFetch();
  try {
    for (const baseUrl of BLOCKED_BASE_URLS) {
      const result = await embedGuideV2Texts({
        texts: ["hello"],
        modelLabel: "btpm-embed",
        dimensions: 1536,
        requestId: "test",
        runtime: embeddingRuntime(baseUrl),
      });
      assert(!result.ok, `${baseUrl} must not be requested`);
      assertEquals(result.error?.code, "endpoint_blocked");
    }
  } finally {
    globalThis.fetch = original;
  }
});

Deno.test("embeddings report a refused redirect as endpoint_blocked", async () => {
  const original = globalThis.fetch;
  let redirectMode: RequestRedirect | undefined;
  globalThis.fetch = ((_url: string, init: RequestInit) => {
    redirectMode = init.redirect;
    return Promise.resolve(
      new Response(null, {
        status: 302,
        headers: { Location: "http://169.254.169.254/latest/meta-data/" },
      }),
    );
  }) as unknown as typeof fetch;
  try {
    const result = await embedGuideV2Texts({
      texts: ["hello"],
      modelLabel: "btpm-embed",
      dimensions: 1536,
      requestId: "test",
      runtime: embeddingRuntime("https://api.example.com/v1"),
    });
    assert(!result.ok);
    assertEquals(result.error?.code, "endpoint_blocked");
    assertEquals(redirectMode, "manual");
  } finally {
    globalThis.fetch = original;
  }
});
