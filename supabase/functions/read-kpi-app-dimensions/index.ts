// BTPM — Step C2-READ.1 (refactored under Phase 4D.14A.2)
// Protected, read-only call to the KPI App `/dimensions` endpoint.
//
// Hard rules:
//   - Auth required + Org Admin authority.
//   - Does NOT mutate any BTPM table.
//   - Does NOT log/return credentials or Authorization headers.
//   - Credentials come from the MuleSoft KPI Tenant integration
//     (`mulesoft_kpi / default`) via the shared resolver. No env-secret reads.

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

function pickArray(obj: any, keys: string[]): any[] | null {
  if (!obj || typeof obj !== "object") return null;
  for (const k of keys) {
    if (Array.isArray(obj[k])) return obj[k];
  }
  return null;
}

function normScenario(raw: any): Record<string, unknown> | null {
  if (!raw || typeof raw !== "object") return null;
  const idRaw = raw.scenario_ID ?? raw.scenario_id ?? raw.scenarioId ?? raw.id ?? raw.ID;
  const id = Number(idRaw);
  if (!Number.isFinite(id)) return null;
  const name = raw.scenario_Name ?? raw.scenario_name ?? raw.scenarioName ?? raw.name ?? null;
  return { scenario_id: id, scenario_name: typeof name === "string" ? name : String(name ?? "") };
}

function normCurrency(raw: any): Record<string, unknown> | null {
  if (!raw || typeof raw !== "object") return null;
  const idRaw = raw.currency_ID ?? raw.currency_id ?? raw.currencyId ?? raw.id ?? raw.ID;
  const id = Number(idRaw);
  if (!Number.isFinite(id)) return null;
  const name =
    raw.currency_Name ?? raw.currency_name ?? raw.currencyName ?? raw.name ?? null;
  const code =
    raw.currency_Code ?? raw.currency_code ?? raw.currencyCode ?? raw.code ?? null;
  return {
    currency_id: id,
    currency_name: typeof name === "string" ? name : String(name ?? ""),
    currency_code: typeof code === "string" ? code : (name ?? null),
  };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return respond({ ok: false, error: "Method not allowed" }, 405);

  const requestId = crypto.randomUUID();

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader)
      return respond({ ok: false, request_id: requestId, error: "Not authenticated" }, 401);

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
    if (!organizationId) {
      return respond({ ok: false, request_id: requestId, error: "organization_id required" }, 400);
    }

    const { data: u, error: ue } = await caller.auth.getUser();
    if (ue || !u?.user?.id) {
      return respond({ ok: false, request_id: requestId, error: "Not authenticated" }, 401);
    }


    // Phase 4D.14A.5A follow-up — accept Org Admin OR Tenant Admin of the
    // owning tenant so the Tenant Admin "Test connection" surface can reuse
    // this read-only edge function.
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


    let cfg;
    try {
      cfg = await resolveTenantMulesoftKpiRuntimeConfig({
        organizationId,
        action: "real_integration",
        reason: "kpi-app-dimensions-read",
        functionName: "read-kpi-app-dimensions",
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

    const url = `${base.origin}/dimensions`;
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
        code: "KPI_DIMENSIONS_NETWORK_ERROR",
        safe_endpoint_summary: { host: base.host, pathname: "/dimensions" },
      });
    }

    if (upstream.status === 401 || upstream.status === 403) {
      await upstream.text().catch(() => "");
      return respond({
        ok: false,
        request_id: requestId,
        code: "KPI_DIMENSIONS_AUTH_FAILED",
        http_status: upstream.status,
        safe_endpoint_summary: { host: base.host, pathname: "/dimensions" },
      });
    }
    if (upstream.status === 404) {
      await upstream.text().catch(() => "");
      return respond({
        ok: false,
        request_id: requestId,
        code: "KPI_DIMENSIONS_ENDPOINT_NOT_FOUND",
        http_status: 404,
        safe_endpoint_summary: { host: base.host, pathname: "/dimensions" },
      });
    }
    if (!upstream.ok) {
      await upstream.text().catch(() => "");
      return respond({
        ok: false,
        request_id: requestId,
        code: "KPI_DIMENSIONS_UPSTREAM_ERROR",
        http_status: upstream.status,
        safe_endpoint_summary: { host: base.host, pathname: "/dimensions" },
      });
    }

    let parsed: any;
    try {
      parsed = await upstream.json();
    } catch {
      return respond({
        ok: false,
        request_id: requestId,
        code: "KPI_DIMENSIONS_INVALID_RESPONSE",
        safe_endpoint_summary: { host: base.host, pathname: "/dimensions" },
      });
    }

    const scenariosArr =
      pickArray(parsed, ["scenarios", "Scenarios", "scenario", "scenarioList"]) ??
      (Array.isArray(parsed?.data?.scenarios) ? parsed.data.scenarios : null);
    const currenciesArr =
      pickArray(parsed, ["currencies", "Currencies", "currency", "currencyList"]) ??
      (Array.isArray(parsed?.data?.currencies) ? parsed.data.currencies : null);

    let scenarios = (scenariosArr ?? [])
      .map(normScenario)
      .filter((r): r is Record<string, unknown> => r !== null);
    let currencies = (currenciesArr ?? [])
      .map(normCurrency)
      .filter((r): r is Record<string, unknown> => r !== null);

    // Flat Type/ID/Description array shape (current real API response).
    let flatRecognized = false;
    let unknownTypeCount = 0;
    const flatSource = Array.isArray(parsed)
      ? parsed
      : Array.isArray((parsed as any)?.data)
        ? (parsed as any).data
        : null;
    if (
      scenarios.length === 0 &&
      currencies.length === 0 &&
      Array.isArray(flatSource) &&
      flatSource.length > 0 &&
      flatSource.some(
        (it) =>
          it &&
          typeof it === "object" &&
          typeof (it as any).Type === "string" &&
          ((it as any).ID !== undefined || (it as any).id !== undefined),
      )
    ) {
      const flatScenarios: Record<string, unknown>[] = [];
      const flatCurrencies: Record<string, unknown>[] = [];
      for (const item of flatSource) {
        if (!item || typeof item !== "object") {
          unknownTypeCount++;
          continue;
        }
        const typeRaw = (item as any).Type ?? (item as any).type;
        const idRaw = (item as any).ID ?? (item as any).id;
        const descRaw =
          (item as any).Description ?? (item as any).description ?? (item as any).Name ?? (item as any).name;
        const id = Number(idRaw);
        const description = typeof descRaw === "string" ? descRaw : descRaw != null ? String(descRaw) : "";
        if (!Number.isFinite(id) || typeof typeRaw !== "string") {
          unknownTypeCount++;
          continue;
        }
        const type = typeRaw.toLowerCase();
        if (type === "scenario") {
          flatScenarios.push({ scenario_id: id, scenario_name: description });
        } else if (type === "currency") {
          flatCurrencies.push({
            currency_id: id,
            currency_name: description,
            currency_code: description,
          });
        } else {
          unknownTypeCount++;
        }
      }
      if (flatScenarios.length > 0 || flatCurrencies.length > 0) {
        scenarios = flatScenarios;
        currencies = flatCurrencies;
        flatRecognized = true;
      }
    }

    if (flatRecognized) {
      return respond({
        ok: true,
        request_id: requestId,
        scenarios,
        currencies,
        raw_response_summary: {
          is_array: true,
          array_length: Array.isArray(flatSource) ? flatSource.length : null,
          recognized_shape: "flat_type_id_description_array",
          unknown_type_count: unknownTypeCount,
        },
        safe_endpoint_summary: { host: base.host, pathname: "/dimensions" },
      });
    }

    if (!scenariosArr && !currenciesArr) {
      // Unknown shape — return safe summary + raw sample so admin can review and parser can be corrected.
      const topKeys =
        parsed && typeof parsed === "object" && !Array.isArray(parsed)
          ? Object.keys(parsed).slice(0, 20)
          : [];
      const sampleSource = Array.isArray(parsed)
        ? parsed
        : Array.isArray((parsed as any)?.data)
          ? (parsed as any).data
          : null;
      const raw_response_sample = sampleSource
        ? sampleSource.slice(0, 10)
        : parsed && typeof parsed === "object"
          ? [parsed]
          : [];
      return respond({
        ok: true,
        request_id: requestId,
        code: "KPI_DIMENSIONS_UNRECOGNIZED_SHAPE",
        message:
          "The KPI App /dimensions endpoint returned a response shape BTPM does not yet recognize.",
        scenarios: [],
        currencies: [],
        raw_response_summary: {
          top_level_keys: topKeys,
          is_array: Array.isArray(parsed),
          array_length: Array.isArray(parsed) ? parsed.length : null,
        },
        raw_response_sample,
        unrecognized_shape: true,
        safe_endpoint_summary: { host: base.host, pathname: "/dimensions" },
      });
    }


    return respond({
      ok: true,
      request_id: requestId,
      scenarios,
      currencies,
      safe_endpoint_summary: { host: base.host, pathname: "/dimensions" },
    });
  } catch {
    return respond({ ok: false, request_id: requestId, error: "Internal error" }, 500);
  }
});
