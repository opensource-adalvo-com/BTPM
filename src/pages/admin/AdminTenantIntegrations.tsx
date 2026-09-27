import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { useActiveContext } from "@/context/ActiveContextProvider";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { SaasAdminShell, AdminLoadingCards, AdminEmptyState } from "./SaasAdminShell";
import { TenantIntegrationDetailDialog } from "@/components/admin/TenantIntegrationDetailDialog";
import { TenantIntegrationSecretSetupDialog } from "@/components/admin/TenantIntegrationSecretSetupDialog";
import { PowerBiReportingReadinessPanel } from "@/components/admin/PowerBiReportingReadinessPanel";
import { useAdminAccess } from "@/hooks/useAdminAccess";
import { toast } from "@/hooks/use-toast";
import { Eye, KeyRound, Power, PowerOff, Sparkles } from "lucide-react";

interface IntegrationRow {
  integration_id: string;
  kind: string;
  name: string;
  status: string;
  is_enabled: boolean;
  active_secret_count: number;
  tenant_secret_count: number;
  organization_override_count: number;
  last_tested_at: string | null;
  last_success_at: string | null;
  last_error_at: string | null;
  last_error_message: string | null;
  has_config_metadata: boolean;
  config_metadata_key_count: number;
  required_secret_count: number;
  configured_required_secret_count: number;
  missing_required_secret_count: number;
  configuration_ready: boolean;
  configuration_issue_code: string | null;
}

interface ProviderReadiness {
  provider: "openai" | "azure_openai";
  present: boolean;
  integration_id?: string | null;
  is_enabled?: boolean;
  status?: string;
  configuration_ready?: boolean;
  secrets_ready?: boolean;
  connection_tested_ok?: boolean;
  ready: boolean;
  issue_code: string | null;
}

interface ProviderSettingResponse {
  tenant_id: string;
  active_provider: "openai" | "azure_openai" | null;
  providers: ProviderReadiness[];
}

const KIND_LABELS: Record<string, string> = {
  openai: "OpenAI",
  azure_openai: "Azure OpenAI",
  microsoft_graph: "Microsoft Graph",
  sharepoint: "SharePoint",
  mulesoft_kpi: "MuleSoft KPI",
  smtp: "SMTP (email)",
  sap: "SAP",
  salesforce: "Salesforce",
  webhook: "Webhook",
  storage_export: "Storage export",
  other: "Other",
};

const PROVIDER_LABELS: Record<string, string> = {
  openai: "OpenAI",
  azure_openai: "Azure OpenAI",
};

const PROVIDER_ISSUE_LABELS: Record<string, string> = {
  integration_missing: "Integration not provisioned",
  integration_disabled: "Not enabled",
  integration_not_active: "Not active",
  // deepcode ignore HardcodedNonCryptoSecret: <please specify a reason of ignoring this>
  missing_required_secrets: "Missing required secrets",
  missing_required_configuration: "Missing required configuration",
  connection_test_not_passed: "Connection test not passed",
  unsupported_provider: "Unsupported provider",
  not_ready: "Not ready",
};

function readinessBadge(row: IntegrationRow) {
  if (row.status === "error") {
    return <Badge variant="outline" className="border-destructive/60 text-destructive">Error</Badge>;
  }
  const hasRequirements = row.required_secret_count > 0;
  const secretsComplete = hasRequirements && row.missing_required_secret_count === 0;
  const configReady = row.configuration_ready !== false;
  const fullyReady = secretsComplete && configReady;
  if (!row.is_enabled || row.status === "disabled") {
    if (fullyReady) {
      return <Badge variant="outline" className="border-sky-500/50 text-sky-700 dark:text-sky-400">Ready to enable</Badge>;
    }
    if (hasRequirements && row.configured_required_secret_count > 0 && !configReady) {
      return <Badge variant="outline" className="border-amber-500/50 text-amber-700 dark:text-amber-400">Configuration incomplete</Badge>;
    }
    if (hasRequirements && row.configured_required_secret_count > 0) {
      return <Badge variant="outline" className="border-amber-500/50 text-amber-700 dark:text-amber-400">Not configured</Badge>;
    }
    return <Badge variant="outline" className="border-amber-500/50 text-amber-700 dark:text-amber-400">Disabled</Badge>;
  }
  if (!fullyReady) {
    return <Badge variant="outline" className="border-destructive/60 text-destructive">Not configured</Badge>;
  }
  return <Badge variant="outline" className="border-green-500/50 text-green-700 dark:text-green-400">Active</Badge>;
}

function providerReadinessBadge(p: ProviderReadiness | undefined, active: boolean) {
  if (!p || !p.present) {
    return <Badge variant="outline" className="border-destructive/60 text-destructive">Not provisioned</Badge>;
  }
  if (p.ready) {
    return (
      <Badge variant="outline" className={active
        ? "border-green-500/60 text-green-700 dark:text-green-400"
        : "border-sky-500/50 text-sky-700 dark:text-sky-400"}>
        {active ? "Active · Ready" : "Ready"}
      </Badge>
    );
  }
  return <Badge variant="outline" className="border-amber-500/50 text-amber-700 dark:text-amber-400">Not ready</Badge>;
}

export default function AdminTenantIntegrations() {
  const ctx = useActiveContext();
  const admin = useAdminAccess();
  const tenantId = ctx.activeTenant?.id ?? null;
  const canConfigure = tenantId ? admin.isTenantAdminForTenant(tenantId) : false;
  const [detailId, setDetailId] = useState<string | null>(null);
  const [setupId, setSetupId] = useState<string | null>(null);
  const [savedProviderNotice, setSavedProviderNotice] = useState<string | null>(null);

  const qc = useQueryClient();

  const { data, isLoading, error } = useQuery({
    queryKey: ["tenant-admin-integrations", tenantId],
    queryFn: async () => {
      const { data, error } = await (supabase.rpc as any)("admin_list_tenant_integrations", {
        _tenant_id: tenantId,
      });
      if (error) throw error;
      return (data ?? []) as IntegrationRow[];
    },
    enabled: !!tenantId,
    staleTime: 30_000,
  });

  const providerQuery = useQuery({
    queryKey: ["tenant-admin-ai-provider", tenantId],
    queryFn: async () => {
      const { data, error } = await (supabase.rpc as any)(
        "tenant_admin_get_ai_provider_setting",
        { _tenant_id: tenantId },
      );
      if (error) throw error;
      return data as ProviderSettingResponse;
    },
    enabled: !!tenantId && canConfigure,
    staleTime: 15_000,
  });

  const providerByKind = useMemo(() => {
    const map: Record<string, ProviderReadiness | undefined> = {};
    (providerQuery.data?.providers ?? []).forEach((p) => { map[p.provider] = p; });
    return map;
  }, [providerQuery.data]);

  const azureRowVisible = useMemo(
    () => !!(data ?? []).find((r) => r.kind === "azure_openai"),
    [data],
  );

  const toggleEnabled = useMutation({
    mutationFn: async (input: { integration_id: string; is_enabled: boolean }) => {
      const { data, error } = await (supabase.rpc as any)(
        "tenant_admin_set_integration_enabled",
        {
          _integration_id: input.integration_id,
          _is_enabled: input.is_enabled,
          _reason: input.is_enabled
            ? "Tenant Admin enabled integration"
            : "Tenant Admin disabled integration",
        },
      );
      if (error) throw error;
      return data;
    },
    onSuccess: (_d, vars) => {
      toast({
        title: vars.is_enabled ? "Integration enabled" : "Integration disabled",
        description: vars.is_enabled
          ? "Integration is now active and ready to send."
          : "Integration is now disabled.",
      });
      qc.invalidateQueries({ queryKey: ["tenant-admin-integrations", tenantId] });
      qc.invalidateQueries({ queryKey: ["tenant-admin-ai-provider", tenantId] });
    },
    onError: (err: any) => {
      toast({
        title: "Action failed",
        description: err?.message ?? "Could not update integration status.",
        variant: "destructive",
      });
    },
  });

  const setProvider = useMutation({
    mutationFn: async (provider: "openai" | "azure_openai") => {
      const { data, error } = await (supabase.rpc as any)(
        "tenant_admin_set_ai_provider",
        {
          _tenant_id: tenantId,
          _provider: provider,
          _reason: "Tenant Admin selected AI provider",
        },
      );
      if (error) throw error;
      return data as { active_provider: string };
    },
    onSuccess: () => {
      setSavedProviderNotice(
        "Provider selection saved. Runtime activation will occur after the AI provider migration is completed.",
      );
      toast({ title: "AI provider updated" });
      qc.invalidateQueries({ queryKey: ["tenant-admin-ai-provider", tenantId] });
    },
    onError: (err: any) => {
      toast({
        title: "Could not set AI provider",
        description: err?.message ?? "The selected provider is not ready.",
        variant: "destructive",
      });
    },
  });

  const active = providerQuery.data?.active_provider ?? null;


  return (
    <SaasAdminShell
      title="Integrations"
      scope="tenant"
      contextLabel={ctx.activeTenant?.name ?? null}
      crumbs={[{ label: "Tenant", to: "/admin/tenant" }, { label: "Integrations" }]}
    >
      <p className="text-xs text-muted-foreground">
        Ordinary integrations below use protected Tenant configuration. Power BI
        Direct reporting is managed separately through its Tenant-bound PostgreSQL
        reporting identity, including readiness and credential lifecycle controls.
      </p>

      {tenantId && <PowerBiReportingReadinessPanel tenantId={tenantId} />}



      {isLoading && <AdminLoadingCards count={2} />}
      {error && (
        <Card>
          <CardContent className="py-6 text-sm text-destructive">Failed to load integrations.</CardContent>
        </Card>
      )}
      {data && data.length === 0 && !canConfigure && (
        <AdminEmptyState
          title="No integrations configured"
          description="Tenant integrations will appear here once configured."
        />
      )}
      {data && (tenantId && canConfigure || data.length > 0) && (

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Tenant integrations</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 p-0">
            {tenantId && canConfigure && (
              <div className="space-y-2 border-b p-4">
                <div className="flex items-center gap-2 text-sm font-medium">
                  <Sparkles className="h-4 w-4" /> AI provider selection
                </div>
                <div className="text-xs text-muted-foreground">
                  One AI provider may be active per Tenant. OpenAI and Azure OpenAI appear
                  below as regular integrations — configure them with the same actions.
                  This selection is configuration-only until the AI provider runtime
                  migration is completed.
                </div>
                <div className="rounded-md border bg-muted/30 px-3 py-2 text-xs">
                  <span className="font-medium">Current selection: </span>
                  {active
                    ? PROVIDER_LABELS[active] ?? active
                    : <span className="text-amber-700 dark:text-amber-400">No AI provider is active.</span>}
                </div>
                {savedProviderNotice && (
                  <div className="rounded-md border border-sky-500/40 bg-sky-500/5 px-3 py-2 text-xs text-sky-700 dark:text-sky-400">
                    {savedProviderNotice}
                  </div>
                )}
                {!azureRowVisible && (
                  <div className="text-xs text-destructive">
                    Azure OpenAI setup is unavailable for this Tenant.
                  </div>
                )}
              </div>
            )}
            {data.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Integration</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Readiness</TableHead>
                  <TableHead className="text-right">Required secrets</TableHead>
                  <TableHead className="text-right">Org overrides</TableHead>
                  <TableHead>Last updated</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {[...data]
                  .sort((a, b) => {
                    const aiOrder = (k: string) => k === "openai" ? 0 : k === "azure_openai" ? 1 : 2;
                    return aiOrder(a.kind) - aiOrder(b.kind);
                  })
                  .map((i) => {
                  const isAiKind = i.kind === "openai" || i.kind === "azure_openai";
                  const providerKind = isAiKind ? (i.kind as "openai" | "azure_openai") : null;
                  const isActiveProvider = providerKind !== null && active === providerKind;
                  const providerReady = providerKind ? providerByKind[providerKind]?.ready === true : false;
                  const missingConfig = i.configuration_ready === false;
                  const disableEnable =
                    !canConfigure ||
                    toggleEnabled.isPending ||
                    i.missing_required_secret_count > 0 ||
                    i.required_secret_count === 0 ||
                    missingConfig;
                  const enableTitle =
                    i.required_secret_count === 0
                      ? "No required secrets defined for this integration"
                      : i.missing_required_secret_count > 0
                        ? `Missing ${i.missing_required_secret_count} required secret(s)`
                        : missingConfig
                          ? "Required configuration is missing"
                          : canConfigure
                            ? "Enable integration"
                            : "Only Tenant Admins may toggle";
                  return (
                    <TableRow key={i.integration_id}>
                      <TableCell className="font-medium">
                        <div className="flex items-center gap-2">
                          {isAiKind && <Sparkles className="h-3.5 w-3.5 text-muted-foreground" />}
                          {KIND_LABELS[i.kind] ?? i.kind}
                        </div>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {i.name}
                        {isActiveProvider && (
                          <Badge variant="outline" className="ml-2 border-green-500/50 text-green-700 dark:text-green-400">
                            AI active
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell>{readinessBadge(i)}</TableCell>
                      <TableCell className="text-right text-xs text-muted-foreground">
                        {i.configured_required_secret_count} / {i.required_secret_count}
                      </TableCell>
                      <TableCell className="text-right text-xs text-muted-foreground">
                        {i.organization_override_count}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {i.last_tested_at ? new Date(i.last_tested_at).toLocaleDateString() : "—"}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex flex-wrap justify-end gap-2">
                          <Button size="sm" variant="outline" onClick={() => setDetailId(i.integration_id)}>
                            <Eye className="h-3.5 w-3.5 mr-1" /> View details
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            disabled={!canConfigure}
                            title={canConfigure ? undefined : "Only Tenant Admins may configure secrets"}
                            onClick={() => setSetupId(i.integration_id)}
                          >
                            <KeyRound className="h-3.5 w-3.5 mr-1" /> Configure
                          </Button>
                          {i.is_enabled ? (
                            <Button
                              size="sm"
                              variant="outline"
                              disabled={!canConfigure || toggleEnabled.isPending || isActiveProvider}
                              title={
                                isActiveProvider
                                  ? "Select another AI provider before disabling this integration."
                                  : canConfigure
                                    ? "Disable integration"
                                    : "Only Tenant Admins may toggle"
                              }
                              onClick={() =>
                                toggleEnabled.mutate({ integration_id: i.integration_id, is_enabled: false })
                              }
                            >
                              <PowerOff className="h-3.5 w-3.5 mr-1" /> Disable
                            </Button>
                          ) : (
                            <Button
                              size="sm"
                              variant="outline"
                              disabled={disableEnable}
                              title={enableTitle}
                              onClick={() =>
                                toggleEnabled.mutate({ integration_id: i.integration_id, is_enabled: true })
                              }
                            >
                              <Power className="h-3.5 w-3.5 mr-1" /> Enable
                            </Button>
                          )}
                          {providerKind && (
                            <Button
                              size="sm"
                              variant="outline"
                              disabled={
                                !canConfigure ||
                                !providerReady ||
                                isActiveProvider ||
                                setProvider.isPending
                              }
                              title={
                                !providerReady
                                  ? "Provider is not ready. Configure secrets, endpoint, and pass a connection test first."
                                  : isActiveProvider
                                    ? "Already active"
                                    : "Set as active AI provider"
                              }
                              onClick={() => setProvider.mutate(providerKind)}
                            >
                              <Sparkles className="h-3.5 w-3.5 mr-1" /> Set active
                            </Button>
                          )}
                        </div>
                      </TableCell>

                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
            )}


          </CardContent>
        </Card>
      )}
      <TenantIntegrationDetailDialog
        open={!!detailId}
        onOpenChange={(v) => !v && setDetailId(null)}
        integrationId={detailId}
      />
      <TenantIntegrationSecretSetupDialog
        open={!!setupId}
        onOpenChange={(v) => !v && setSetupId(null)}
        integrationId={setupId}
      />
    </SaasAdminShell>
  );
}
