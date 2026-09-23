# BTPM

BTPM is an execution-focused Business Transformation and Project Management platform for running complex cross-functional initiatives without turning project delivery into an over-configured PPM exercise.

The product combines structured planning and execution, portfolio visibility, governed collaboration, KPI tracking, risks and blockers, reporting, and integration surfaces for conventional applications and AI agents.

**Note: This is a fork of the original repo. Due to a tragic incident, access was lost to the original repo.**

## What BTPM covers

BTPM models delivery around a structured hierarchy:

```text
Tenant / Organization
        |
        +-- Workspace
              |
              +-- Program
              |     |
              |     +-- Project
              |
              +-- Project
                    |
                    +-- Phase
                          |
                          +-- Task
```

Cross-cutting capabilities include Programs, Projects, Phases, Tasks and milestones; dependencies and schedule control; Risks and Blockers; ownership and RACI-style accountability; execution updates and comments; KPI definitions and history; portfolio visibility; roadmap and reporting surfaces; governed REST API integration; MCP tools; and Tenant / Organization / Workspace / Project containment.

## Architecture

BTPM is a React/TypeScript application backed by PostgreSQL/Supabase, with protected server-side functions and Edge Functions for controlled integration paths.

```text
Browser / external application / AI agent
                    |
          +---------+---------+
          |                   |
       Web app            REST / MCP
          |                   |
          +---------+---------+
                    |
          BTPM business authority
                    |
        PostgreSQL / Supabase
```

Primary technologies include React, TypeScript, Vite, Supabase/PostgreSQL, Deno Edge Functions, TanStack Query, shadcn/ui and the Model Context Protocol SDK.

## Installation and configuration

For a new deployment, start with the complete [BTPM first-install and configuration guide](./docs/SETUP.md). It covers the full setup sequence, including:

- creating and linking a fresh Supabase project;
- applying the clean migration baseline;
- configuring browser and Edge Function environment values;
- creating and bootstrapping the first BTPM Tenant / Organization / Workspace;
- validating the built-in Tenant encryption-key lifecycle;
- configuring email/password authentication and optional Microsoft sign-in;
- configuring BTPM Connected Apps, OAuth, REST API and MCP access;
- configuring the currently supported protected Tenant integrations and the correct pattern for other external systems;
- production hardening and post-install validation.

Detailed configuration references:

- [Supabase setup](./docs/configuration/SUPABASE.md)
- [Environment variables and runtime secrets](./docs/configuration/ENVIRONMENT.md)
- [Authentication and Microsoft SSO](./docs/configuration/AUTHENTICATION_AND_SSO.md)
- [OAuth and Connected Apps](./docs/configuration/OAUTH_AND_CONNECTED_APPS.md)
- [Encryption](./docs/configuration/ENCRYPTION.md)
- [Optional integrations](./docs/configuration/OPTIONAL_INTEGRATIONS.md)

## Fresh installation

### Prerequisites

- Node.js and npm
- Supabase CLI
- a new, non-production Supabase project for the first validation pass

Never bootstrap a first installation against an existing production database.

### 1. Configure the web application

Copy `.env.example` to your local environment file and provide values for your own Supabase project. Do not commit real credentials or production identifiers.

### 2. Apply the database baseline

The `supabase/migrations/` directory is a clean first-install baseline. Apply it to an empty Supabase project using the normal Supabase migration workflow.

The baseline includes required extensions, the canonical public schema, protected API executors, Power BI reporting security substrate and storage policy contract. See `supabase/DEPENDENCY_MANIFEST.md` for ordering and dependency notes.

### 3. Create the first Auth user

Create the first Supabase Auth user through the normal Supabase authentication flow. The database baseline intentionally does not embed a deployment-specific user, Tenant, Organization or Workspace.

### 4. Bootstrap the first BTPM context

Use `supabase/bootstrap/first_install.sql` as the operator bootstrap template for the first Tenant / Organization / Workspace and initial administrator context. Replace only the documented placeholders with values belonging to your deployment.

The bootstrap creates fresh Tenant encryption material through the approved BTPM key lifecycle. Do not import encryption material from another deployment and do not invent an application-level encryption-key environment variable.

### 5. Run the application

```bash
npm ci
npm run dev
```

For production builds:

```bash
npm run build
```

Continue with [docs/SETUP.md](./docs/SETUP.md) before treating the installation as production-ready.

## Validation

Principal repository checks are:

```bash
npm run lint
npm test
npm run build
npm run test:mcp
```

The initial open-source baseline carries inherited repository-wide lint debt from its prior development history. `npm run lint` is therefore an advisory whole-repository signal for the first public release rather than a zero-finding acceptance gate. Contributors should still resolve lint findings they introduce or materially touch and must not use the inherited baseline to justify new lint regressions.

Changes to database, Edge Function, API, MCP, authorization, tenant containment or encryption surfaces require targeted review beyond build success.

## Integration documentation

- [Integration overview](./docs/integrations/README.md)
- [REST API v1](./docs/integrations/REST_API.md)
- [BTPM MCP](./docs/integrations/MCP.md)
- [REST / MCP capability matrix](./docs/integrations/CAPABILITY_MATRIX.md)
- [Integration security and administration](./docs/integrations/SECURITY_AND_ADMINISTRATION.md)

Executable source remains authoritative for runtime contracts.

## Repository map

```text
src/                                      Web application
supabase/migrations/                       Clean first-install database baseline
supabase/bootstrap/                        First-install operator bootstrap
supabase/functions/_shared/btpm-api/      Canonical API contracts and adapters
supabase/functions/btpm-api-v1/           REST API Edge Function
supabase/functions/btpm-mcp/              MCP Edge Function and tools
supabase/edge-tests/                       Edge/API/MCP regression tests
scripts/                                  Build, validation and engineering tooling
docs/configuration/                       Deployment and configuration reference
docs/integrations/                        Current integration documentation
docs/governance/                          Architecture and engineering governance material
```

## Security

BTPM includes authorization, Tenant / Workspace / Project containment, RLS, protected backend paths and governed encrypted handling. Read [SECURITY.md](./SECURITY.md) before reporting a vulnerability or changing authentication, authorization, encryption, tenant containment, database policies or integration boundaries.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

BTPM is licensed under the [MIT License](./LICENSE).
