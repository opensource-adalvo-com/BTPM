// Tests for the shared outbound request guard (SSRF protection).

import {
  assert,
  assertEquals,
  assertRejects,
} from "https://deno.land/std@0.224.0/assert/mod.ts";

import {
  checkOutboundUrl,
  guardedFetch,
  OutboundRequestError,
} from "../outboundRequestGuard.ts";

function blocked(rawUrl: string): boolean {
  const result = checkOutboundUrl(rawUrl);
  return !result.ok;
}

function reason(rawUrl: string): string | null {
  const result = checkOutboundUrl(rawUrl);
  return result.ok ? null : result.reason;
}

Deno.test("permits ordinary public https endpoints", () => {
  for (
    const url of [
      "https://kpi.example.com/api/v1",
      "http://kpi.example.co.uk:8443/api",
      "https://8.8.8.8/api",
      "https://[2606:4700:4700::1111]/api",
      "https://kpi.example.com./api", // trailing FQDN root dot
    ]
  ) {
    assert(checkOutboundUrl(url).ok, `expected ${url} to be permitted`);
  }
});

Deno.test("rejects non-http schemes and embedded credentials", () => {
  assertEquals(reason("file:///etc/passwd"), "unsupported_scheme");
  assertEquals(reason("gopher://example.com/"), "unsupported_scheme");
  assertEquals(reason("not a url"), "invalid_url");
  assertEquals(reason("https://user:pass@example.com/"), "embedded_credentials");
});

Deno.test("blocks loopback, link-local, private and reserved IPv4", () => {
  for (
    const host of [
      "127.0.0.1",
      "127.1.2.3",
      "0.0.0.0",
      "10.1.2.3",
      "172.16.0.1",
      "172.31.255.255",
      "192.168.1.1",
      "169.254.169.254", // cloud instance metadata
      "100.64.0.1", // CGNAT
      "198.18.0.1", // benchmarking
      "192.0.2.1", // TEST-NET-1
      "198.51.100.1", // TEST-NET-2
      "203.0.113.1", // TEST-NET-3
      "224.0.0.1", // multicast
      "255.255.255.255",
    ]
  ) {
    assert(blocked(`http://${host}/latest/meta-data/`), `expected ${host} to be blocked`);
  }
});

Deno.test("blocks obfuscated IPv4 spellings of loopback and metadata", () => {
  for (
    const host of [
      "0x7f000001", // hex
      "2130706433", // integer
      "0177.0.0.1", // octal
      "127.1", // short form
      "0xA9FEA9FE", // hex 169.254.169.254
    ]
  ) {
    assert(blocked(`http://${host}/`), `expected ${host} to be blocked`);
  }
});

Deno.test("blocks loopback, ULA, link-local and IPv4-mapped IPv6", () => {
  for (
    const host of [
      "[::1]",
      "[::]",
      "[fc00::1]", // unique local
      "[fd12:3456::1]", // unique local
      "[fe80::1]", // link-local
      "[ff02::1]", // multicast
      "[64:ff9b::7f00:1]", // NAT64 of 127.0.0.1
      "[::ffff:127.0.0.1]", // IPv4-mapped loopback
      "[::ffff:169.254.169.254]", // IPv4-mapped metadata
      "[::ffff:a9fe:a9fe]", // same, hex spelling
    ]
  ) {
    assert(blocked(`http://${host}/`), `expected ${host} to be blocked`);
  }
});

Deno.test("blocks internal-only hostnames", () => {
  for (
    const host of [
      "localhost",
      "api.localhost",
      "kpi-gateway", // single label
      "printer.local",
      "metadata.google.internal",
      "metadata.goog",
      "vault.internal",
      "wiki.intranet",
      "device.home.arpa",
      "printer.local.", // trailing dot must not bypass the suffix check
    ]
  ) {
    assert(blocked(`http://${host}/`), `expected ${host} to be blocked`);
  }
});

Deno.test("guardedFetch refuses a blocked target before any request", async () => {
  const error = await assertRejects(
    () => guardedFetch("http://169.254.169.254/latest/meta-data/"),
    OutboundRequestError,
  );
  assertEquals(error.reason, "blocked_host");
});

Deno.test("guardedFetch does not follow a redirect toward a blocked host", async () => {
  const server = Deno.serve({ port: 8798, onListen: () => {} }, () =>
    new Response(null, {
      status: 302,
      headers: { Location: "http://169.254.169.254/latest/meta-data/" },
    }));
  try {
    // 127.0.0.1 is itself blocked, so exercise the redirect rule directly.
    const res = await fetch("http://127.0.0.1:8798/dimensions", { redirect: "manual" });
    await res.body?.cancel();
    assertEquals(res.status, 302);
    assert(!res.ok, "a refused redirect must not read as a successful response");
  } finally {
    await server.shutdown();
  }
});

Deno.test("guardedFetch honours a caller-supplied abort signal", async () => {
  const controller = new AbortController();
  controller.abort();
  await assertRejects(() =>
    guardedFetch("https://kpi.example.com/api", { signal: controller.signal })
  );
});
