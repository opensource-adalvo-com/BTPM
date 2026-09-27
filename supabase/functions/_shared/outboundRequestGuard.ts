// BTPM — Outbound request guard (Edge/shared).
//
// Pure, dependency-free. Hardens server-side calls to tenant-configured URLs
// against server-side request forgery (SSRF).
//
// A Tenant Admin controls integration endpoint values (e.g. the MuleSoft KPI
// `api_url` secret). Without a guard those values let an Edge Function be
// aimed at infrastructure the caller cannot otherwise reach — cloud instance
// metadata (169.254.169.254), loopback services, or anything inside the
// private network — with the function's own credentials attached and the
// upstream body echoed back to the caller.
//
// Two rules matter together, and neither is sufficient alone:
//   1. `checkOutboundUrl` rejects loopback, link-local, private, CGNAT and
//      reserved literals plus internal-only hostnames, before the request.
//   2. Redirects are never followed. A permitted public host answering 302
//      Location: http://169.254.169.254/... would otherwise walk straight
//      past rule 1, because `fetch` follows redirects by default.
//
// `guardedFetch` applies both, and returns any 3xx to the caller as a plain
// unsuccessful response (`Response.ok` is false for 3xx) rather than
// following it.
//
// Known limit: DNS is not resolved here — the Edge runtime exposes no
// resolver — so a public hostname that resolves to a private address is not
// caught. Literal addresses, internal suffixes and redirects are.

export type OutboundUrlRejectionReason =
  | "invalid_url"
  | "unsupported_scheme"
  | "embedded_credentials"
  | "blocked_host";

export type OutboundUrlCheck =
  | { ok: true; url: URL }
  | { ok: false; reason: OutboundUrlRejectionReason };

export class OutboundRequestError extends Error {
  reason: OutboundUrlRejectionReason | "timeout";
  constructor(reason: OutboundUrlRejectionReason | "timeout", message: string) {
    super(message);
    this.reason = reason;
    this.name = "OutboundRequestError";
  }
}

/** Hostnames that only ever name something inside the perimeter. */
const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",
  "metadata.goog",
  "instance-data",
]);

const BLOCKED_HOSTNAME_SUFFIXES = [
  ".localhost",
  ".local",
  ".internal",
  ".intranet",
  ".home.arpa",
];

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function isIpv4Literal(host: string): boolean {
  return IPV4_RE.test(host);
}

/**
 * True for any IPv4 address that must not be reachable from an Edge Function.
 * Returns false for hosts that are not IPv4 literals.
 *
 * The WHATWG URL parser canonicalises IPv4 to dotted decimal, so the
 * octal/hex/integer spellings (`0177.0.0.1`, `0x7f000001`, `2130706433`)
 * arrive here already normalised to `127.0.0.1`.
 */
function isBlockedIpv4(host: string): boolean {
  const m = IPV4_RE.exec(host);
  if (!m) return false;
  const [a, b, c] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const octets = [a, b, c, Number(m[4])];
  if (octets.some((n) => n > 255)) return true; // not addressable — fail closed
  if (a === 0) return true; // 0.0.0.0/8 "this network"
  if (a === 10) return true; // RFC1918
  if (a === 127) return true; // loopback
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10
  if (a === 169 && b === 254) return true; // link-local — cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // RFC1918
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return true; // protocol assignments, TEST-NET-1
  if (a === 192 && b === 168) return true; // RFC1918
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  if (a === 198 && b === 51 && c === 100) return true; // TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return true; // TEST-NET-3
  if (a >= 224) return true; // multicast, reserved, broadcast
  return false;
}

/**
 * Expand a compressed IPv6 text form into its eight 16-bit groups, or null if
 * it does not parse. An embedded IPv4 tail (`::ffff:127.0.0.1`) is folded into
 * the last two groups first.
 */
function expandIpv6(inner: string): number[] | null {
  let text = inner;
  const tail = /:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(text);
  if (tail) {
    const octets = tail[1].split(".").map(Number);
    if (octets.some((n) => n > 255)) return null;
    const hi = (octets[0] << 8) | octets[1];
    const lo = (octets[2] << 8) | octets[3];
    text = `${text.slice(0, tail.index)}:${hi.toString(16)}:${lo.toString(16)}`;
  }

  const halves = text.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] === "" ? [] : halves[0].split(":");
  const rest = halves.length === 2 ? (halves[1] === "" ? [] : halves[1].split(":")) : [];

  let groups: string[];
  if (halves.length === 2) {
    const fill = 8 - head.length - rest.length;
    if (fill < 0) return null;
    groups = [...head, ...Array(fill).fill("0"), ...rest];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;

  const out: number[] = [];
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    out.push(parseInt(g, 16));
  }
  return out;
}

/**
 * True for any bracketed IPv6 literal that must not be reachable. Unparseable
 * literals are blocked rather than passed through.
 */
function isBlockedIpv6(host: string): boolean {
  if (!host.startsWith("[") || !host.endsWith("]")) return false;
  const groups = expandIpv6(host.slice(1, -1).toLowerCase());
  if (!groups) return true; // fail closed

  const [g0, g1] = groups;
  if (groups.slice(0, 7).every((g) => g === 0) && groups[7] <= 1) return true; // :: and ::1
  if ((g0 & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
  if ((g0 & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if (g0 === 0x64 && g1 === 0xff9b) return true; // 64:ff9b::/96 NAT64
  if ((g0 & 0xff00) === 0xff00) return true; // ff00::/8 multicast

  // IPv4-mapped (::ffff:0:0/96) and IPv4-compatible (::/96) — the URL parser
  // re-serialises the embedded address as hex, so rebuild it before checking.
  if (groups.slice(0, 5).every((g) => g === 0) && (groups[5] === 0xffff || groups[5] === 0)) {
    const [g6, g7] = [groups[6], groups[7]];
    if (isBlockedIpv4(`${g6 >> 8}.${g6 & 0xff}.${g7 >> 8}.${g7 & 0xff}`)) return true;
  }
  return false;
}

function isBlockedHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, ""); // drop FQDN root dot
  if (host === "") return true;
  if (BLOCKED_HOSTNAMES.has(host)) return true;
  if (BLOCKED_HOSTNAME_SUFFIXES.some((suffix) => host.endsWith(suffix))) return true;
  // Single-label names ("kpi-gateway") resolve only inside a private network;
  // a real external endpoint is always fully qualified.
  if (!host.includes(".")) return true;
  return false;
}

/**
 * Vet a URL before any server-side request is made to it.
 * Accepts only http/https, without embedded credentials, aimed at a host that
 * is not loopback, link-local, private, reserved or internal-only.
 */
export function checkOutboundUrl(rawUrl: string): OutboundUrlCheck {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { ok: false, reason: "invalid_url" };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { ok: false, reason: "unsupported_scheme" };
  }
  if (url.username !== "" || url.password !== "") {
    return { ok: false, reason: "embedded_credentials" };
  }

  const hostname = url.hostname;
  const blocked = hostname.startsWith("[")
    ? isBlockedIpv6(hostname)
    : isIpv4Literal(hostname)
      ? isBlockedIpv4(hostname)
      : isBlockedHostname(hostname);
  if (blocked) return { ok: false, reason: "blocked_host" };

  return { ok: true, url };
}

/**
 * `fetch` with the SSRF guards applied: the URL is vetted, redirects are
 * refused rather than followed, and the request is bounded by a timeout.
 *
 * Throws `OutboundRequestError` when the URL is rejected or the timeout
 * elapses. A 3xx is returned to the caller as an unsuccessful `Response`
 * (`ok === false`) — it is never followed.
 */
export async function guardedFetch(
  rawUrl: string,
  init: RequestInit = {},
  opts: { timeoutMs?: number } = {},
): Promise<Response> {
  const check = checkOutboundUrl(rawUrl);
  if (!check.ok) {
    throw new OutboundRequestError(check.reason, "Outbound URL is not permitted.");
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 30_000);
  // A caller-supplied signal must still be honoured — the timeout is an
  // additional bound on the request, not a replacement for the caller's.
  const callerSignal = init.signal;
  const onCallerAbort = () => controller.abort();
  callerSignal?.addEventListener("abort", onCallerAbort, { once: true });
  if (callerSignal?.aborted) controller.abort();

  try {
    return await fetch(check.url.toString(), {
      ...init,
      redirect: "manual",
      signal: controller.signal,
    });
  } catch (e) {
    if (controller.signal.aborted && !callerSignal?.aborted) {
      throw new OutboundRequestError("timeout", "Outbound request timed out.");
    }
    throw e;
  } finally {
    clearTimeout(timer);
    callerSignal?.removeEventListener("abort", onCallerAbort);
  }
}
