// BTPM — Step C2-READ.1 (refactored under Phase 4D.14A.2)
// Protected, read-only call to the KPI App `/kpis?maintainerEmail=...` endpoint.
//
// Hard rules:
//   - Auth required + Org Admin authority.
//   - Does NOT mutate any BTPM table.
//   - Does NOT log/return credentials, Authorization headers, or secret names.
//   - Credentials come from the MuleSoft KPI Tenant integration
//     (`mulesoft_kpi / default`) resolved by
//     `resolveTenantMulesoftKpiRuntimeConfig`. No Global env-secret reads.

import { createClient } from "npm:@supabase/supabase-js@2";
import { assertBrowserSessionOnly } from "../_shared/btpm-api/assertBrowserSessionOnly.ts";
import { createSupabaseTokenVerifier } from "../_shared/btpm-api/resolveTokenContext.ts";
import { toSafeErrorResponse } from "../_shared/btpm-api/apiErrors.ts";
import {
  resolveTenantMulesoftKpiRuntimeConfig,
  toSafeMulesoftKpiPublicError,
} from "../_shared/tenantMulesoftKpi.ts";
import {
  type AuthorityCheckDeps,
  evaluateAuthority,
} from "../_shared/adminAuthority.ts";
import {
  guardedFetch,
  OutboundRequestError,
} from "../_shared/outboundRequestGuard.ts";



const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function respond(body: Record<string, unknown>, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

function deriveBaseHost(rawUrl: string): { host: string; origin: string } | null {
  try {
    const u = new URL(rawUrl);
    return { host: u.host, origin: `${u.protocol}//${u.host}` };
  } catch {
    return null;
  }
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;


function normalizeRow(raw: any): Record<string, unknown> | null {
  if (!raw || typeof raw !== "object") return null;
  const idRaw = raw.kPI_ID ?? raw.kpi_id ?? raw.id ?? raw.KPI_ID;
  const id = typeof idRaw === "number" ? idRaw : Number(idRaw);
  if (!Number.isFinite(id)) return null;
  const nameRaw = raw.kPI_Name ?? raw.kpi_name ?? raw.name ?? raw.KPI_Name;
  return {
    external_kpi_id: id,
    external_kpi_name: typeof nameRaw === "string" ? nameRaw : String(nameRaw ?? ""),
    category: typeof raw.category === "string" ? raw.category : null,
    value_type: typeof raw.value_Type === "string" ? raw.value_Type : (raw.value_type ?? null),
    description: typeof raw.description === "string" ? raw.description : null,
    update_frequency:
      typeof raw.update_Frequency === "string"
        ? raw.update_Frequency
        : (raw.update_frequency ?? null),
    is_corporate: !!(raw.is_Corporate ?? raw.is_corporate),
    is_top10: !!(raw.is_Top10 ?? raw.is_top10),
    is_departmental: !!(raw.is_Departmental ?? raw.is_departmental),
    is_individual: !!(raw.is_Individual ?? raw.is_individual),
  };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return respond({ ok: false, error: "Method not allowed" }, 405);

  const requestId = crypto.randomUUID();

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) return respond({ ok: false, request_id: requestId, error: "Not authenticated" }, 401);

    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!supabaseUrl || !anonKey || !serviceRoleKey) {
      return respond({ ok: false, request_id: requestId, error: "Server misconfigured" }, 500);
    }

    const caller = createClient(supabaseUrl, anonKey, {
      global: { headers: { Authorization: authHeader } },
    });

    try {
      const verifier = createSupabaseTokenVerifier(caller);
      await assertBrowserSessionOnly(req, verifier);
    } catch (guardError) {
      return toSafeErrorResponse(guardError, corsHeaders);
    }

    const body = await req.json().catch(() => ({} as Record<string, unknown>));
    const organizationId =
      typeof body.organization_id === "string" ? body.organization_id.trim() : "";
    const maintainerEmail =
      typeof body.maintainer_email === "string" ? body.maintainer_email.trim() : "";

    if (!organizationId) {
      return respond({ ok: false, request_id: requestId, error: "organization_id required" }, 400);
    }
    if (!EMAIL_RE.test(maintainerEmail) || maintainerEmail.length > 254) {
      return respond({ ok: false, request_id: requestId, error: "Invalid maintainer_email" }, 400);
    }

    const { data: u, error: ue } = await caller.auth.getUser();
    if (ue || !u?.user?.id) {
      return respond({ ok: false, request_id: requestId, error: "Not authenticated" }, 401);
    }


    // Phase 4D.14A.5A follow-up — accept Org Admin OR Tenant Admin of the
    // owning tenant so the Tenant Admin "Test connection" surface can reuse
    // this read-only edge function. Tenant Admin authority still resolves
    // credentials from the Tenant integration.
    const service = createClient(supabaseUrl, serviceRoleKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const deps: AuthorityCheckDeps = {
      fetchOrgTenant: async (orgId) => {
        const { data, error } = await service
          .from("organizations")
          .select("id, tenant_id")
          .eq("id", orgId)
          .maybeSingle();
        if (error) return { tenantId: null, error: true };
        return {
          tenantId: (data?.tenant_id as string | null | undefined) ?? null,
          error: false,
        };
      },
      isOrgAdmin: async (uid, oid) => {
        const { data, error } = await service.rpc("is_org_admin", {
          _user_id: uid,
          _organization_id: oid,
        });
        if (error) return { value: null, error: true };
        return { value: !!data, error: false };
      },
      isTenantAdmin: async (uid, tid) => {
        const { data, error } = await service.rpc("is_tenant_admin", {
          _tenant_id: tid,
          _user_id: uid,
        });
        if (error) return { value: null, error: true };
        return { value: !!data, error: false };
      },
    };
    const authority = await evaluateAuthority(u.user.id, organizationId, deps);
    if (authority.outcome === "infra_failure") {
      return respond({ ok: false, request_id: requestId, error: "Authority check failed" }, 403);
    }
    if (authority.outcome === "denied") {
      return respond({ ok: false, request_id: requestId, error: "Admin access required" }, 403);
    }


    // Resolve MuleSoft KPI runtime credentials from the Tenant integration
    // for the authorized Organization. No Global env-secret reads.
    let cfg;
    try {
      cfg = await resolveTenantMulesoftKpiRuntimeConfig({
        organizationId,
        action: "real_integration",
        reason: "kpi-app-catalog-read",
        functionName: "read-kpi-app-catalog",
        requestId,
      });
    } catch (e) {
      const safe = toSafeMulesoftKpiPublicError(e);
      return respond({
        ok: false,
        request_id: requestId,
        code: safe.code,
        error: safe.message,
      });
    }
    const base = deriveBaseHost(cfg.apiUrl);
    if (!base) {
      return respond({
        ok: false,
        request_id: requestId,
        code: "MULESOFT_KPI_API_URL_INVALID",
        error: "MuleSoft KPI Tenant integration API URL is invalid.",
      });
    }

    const url = `${base.origin}/kpis?maintainerEmail=${encodeURIComponent(maintainerEmail)}`;
    const basic = btoa(`${cfg.username}:${cfg.password}`);


    // `url` derives from the Tenant Admin-controlled `api_url` secret, so it is
    // untrusted: `guardedFetch` re-checks the composed target against the
    // outbound guard and refuses to follow redirects, so a permitted public
    // host cannot bounce this request onto instance metadata or a loopback
    // service with the Basic credentials attached.
    let upstream: Response;
    try {
      upstream = await guardedFetch(url, {
        method: "GET",
        headers: { Authorization: `Basic ${basic}`, Accept: "application/json" },
      });
    } catch (fetchError) {
      if (
        fetchError instanceof OutboundRequestError &&
        fetchError.reason !== "timeout"
      ) {
        return respond({
          ok: false,
          request_id: requestId,
          code: "MULESOFT_KPI_API_URL_INVALID",
          error: "MuleSoft KPI Tenant integration API URL is invalid.",
        });
      }
      return respond({
        ok: false,
        request_id: requestId,
        code: "KPI_CATALOG_NETWORK_ERROR",
        safe_endpoint_summary: { host: base.host, pathname: "/kpis" },
      });
    }

    if (upstream.status === 401 || upstream.status === 403) {
      await upstream.text().catch(() => "");
      return respond({
        ok: false,
        request_id: requestId,
        code: "KPI_CATALOG_AUTH_FAILED",
        http_status: upstream.status,
        safe_endpoint_summary: { host: base.host, pathname: "/kpis" },
      });
    }
    if (upstream.status === 404) {
      await upstream.text().catch(() => "");
      return respond({
        ok: false,
        request_id: requestId,
        code: "KPI_CATALOG_ENDPOINT_NOT_FOUND",
        http_status: 404,
        safe_endpoint_summary: { host: base.host, pathname: "/kpis" },
      });
    }
    if (!upstream.ok) {
      await upstream.text().catch(() => "");
      return respond({
        ok: false,
        request_id: requestId,
        code: "KPI_CATALOG_UPSTREAM_ERROR",
        http_status: upstream.status,
        safe_endpoint_summary: { host: base.host, pathname: "/kpis" },
      });
    }

    let parsed: unknown;
    try {
      parsed = await upstream.json();
    } catch {
      return respond({
        ok: false,
        request_id: requestId,
        code: "KPI_CATALOG_INVALID_RESPONSE",
        safe_endpoint_summary: { host: base.host, pathname: "/kpis" },
      });
    }

    const arr = Array.isArray(parsed)
      ? parsed
      : Array.isArray((parsed as any)?.kpis)
        ? (parsed as any).kpis
        : Array.isArray((parsed as any)?.data)
          ? (parsed as any).data
          : null;
    if (!arr) {
      return respond({
        ok: false,
        request_id: requestId,
        code: "KPI_CATALOG_INVALID_RESPONSE",
        safe_endpoint_summary: { host: base.host, pathname: "/kpis" },
      });
    }
    const rows = arr.map(normalizeRow).filter((r): r is Record<string, unknown> => r !== null);

    return respond({
      ok: true,
      request_id: requestId,
      maintainer_email: maintainerEmail,
      row_count: rows.length,
      rows,
      safe_endpoint_summary: { host: base.host, pathname: "/kpis" },
    });
  } catch {
    return respond({ ok: false, request_id: requestId, error: "Internal error" }, 500);
  }
});
