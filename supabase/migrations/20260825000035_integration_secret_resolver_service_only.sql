-- SEC — Vault-touching functions are service-role only.
-- Forward-only. Privilege-only change; no function body, table or policy is
-- altered.
--
-- public.resolve_effective_integration_secret_value(...) is SECURITY DEFINER,
-- reads vault.decrypted_secrets and returns the plaintext secret. It performs
-- no caller authorization (auth.uid() is only recorded in the audit row), and
-- the baseline schema granted it to anon and authenticated. Any browser
-- session could therefore read every tenant's integration secrets via RPC.
-- public.resolve_effective_integration_secret_ref(...) had the same grants and
-- discloses Vault ids and fingerprints.
--
-- The remaining Vault-touching functions were only revoked FROM PUBLIC in the
-- baseline. On a fresh Supabase install the schema default privileges grant
-- EXECUTE on new public functions to anon and authenticated, which REVOKE ...
-- FROM PUBLIC does not remove. Revoke those explicitly as well.
--
-- All of these are only called server-side through the service-role client
-- (e.g. functions/_shared/tenantIntegrationSecrets.ts,
-- functions/_shared/tenantSmtp.ts, functions/admin-users/index.ts) or from
-- other SECURITY DEFINER functions.
--
-- Guarded by src/lib/__tests__/vaultSecretFunctionPrivilegeGuard.test.ts.

REVOKE ALL ON FUNCTION public.resolve_effective_integration_secret_value(uuid, uuid, public.tenant_integration_kind, text, text, text, text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.resolve_effective_integration_secret_value(uuid, uuid, public.tenant_integration_kind, text, text, text, text, text) TO service_role;

REVOKE ALL ON FUNCTION public.resolve_effective_integration_secret_ref(uuid, uuid, public.tenant_integration_kind, text, text, text, text, text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.resolve_effective_integration_secret_ref(uuid, uuid, public.tenant_integration_kind, text, text, text, text, text) TO service_role;

REVOKE ALL ON FUNCTION public.admin_store_tenant_secret(uuid, uuid, text, text, text, text, public.tenant_secret_scope, text, uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.admin_store_tenant_secret(uuid, uuid, text, text, text, text, public.tenant_secret_scope, text, uuid) TO service_role;

REVOKE ALL ON FUNCTION public.btpm_decrypt(text, uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.btpm_decrypt(text, uuid) TO service_role;

REVOKE ALL ON FUNCTION public.btpm_decrypt_tenant_versioned(text, uuid, uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.btpm_decrypt_tenant_versioned(text, uuid, uuid) TO service_role;

REVOKE ALL ON FUNCTION public.btpm_decrypt_v2(text, uuid, uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.btpm_decrypt_v2(text, uuid, uuid) TO service_role;

REVOKE ALL ON FUNCTION public.btpm_encrypt_tenant_versioned(text, uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.btpm_encrypt_tenant_versioned(text, uuid) TO service_role;

REVOKE ALL ON FUNCTION public.btpm_encrypt_v2(text, uuid, uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.btpm_encrypt_v2(text, uuid, uuid) TO service_role;

REVOKE ALL ON FUNCTION public.check_tenant_legacy_encryption_key_equivalence(uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.check_tenant_legacy_encryption_key_equivalence(uuid) TO service_role;

REVOKE ALL ON FUNCTION public.ensure_active_tenant_encryption_key_version(uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.ensure_active_tenant_encryption_key_version(uuid) TO service_role;

REVOKE ALL ON FUNCTION public.ensure_org_encryption_key(uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.ensure_org_encryption_key(uuid) TO service_role;

REVOKE ALL ON FUNCTION public.ensure_tenant_encryption_key_v1_from_legacy(uuid) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.ensure_tenant_encryption_key_v1_from_legacy(uuid) TO service_role;
