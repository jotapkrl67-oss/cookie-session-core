# Cookie Session Core

Backend headless para ser conectado a um projeto **Lovable/Supabase existente**.
O Lovable continua responsável por login, usuários, permissões, layout e navegação.
Este container cuida somente de cookies criptografados e sessões Playwright.

## O que está pronto

- API FastAPI autenticada com JWT do Supabase;
- compatibilidade com JWT assimétrico via JWKS e projetos legados HS256;
- autorização administrativa intermediada pela Edge Function do projeto existente;
- importação DevTools, JSON, Netscape e Cookie header;
- AES-256-GCM com chave derivada por usuário e serviço;
- token de lançamento com 30 segundos e consumo único;
- Chromium/Playwright isolado por abertura;
- interface remota por WebSocket e canvas;
- sincronização de cookies rotacionados;
- auditoria sem valores sensíveis;
- Dockerfile e configuração Railway;
- migration PostgreSQL/Supabase com tabelas prefixadas;
- inicialização idempotente das tabelas em PostgreSQL próprio do Railway;
- Edge Function e cliente TypeScript de integração.

## Arquitetura

```text
Projeto Lovable existente
  ├── componentes e rotas atuais
  ├── Supabase Auth atual
  └── cookieCoreClient.ts
          │
          ▼
Supabase Edge Function cookie-core
  ├── valida JWT
  ├── usa a regra de administrador já existente
  └── adiciona segredo interno somente em operações administrativas
          │
          ▼
Container Railway
  ├── FastAPI
  ├── Cookie Session Core
  ├── Chromium + Playwright
  └── WebSocket remoto
          │
          ▼
PostgreSQL do Supabase ou Railway
```

Quando o banco for o PostgreSQL do próprio Railway, configure
`DATABASE_URL=${{Postgres.DATABASE_URL}}`. As tabelas prefixadas são criadas
automaticamente na inicialização; o Lovable Cloud continua responsável pela
autenticação e pela integração server-side.

## Estrutura

```text
Dockerfile
railway.toml
sql/schema.sql
src/cookie_session_core/
  app.py
  auth.py
  browser_manager.py
  config.py
  core.py
  parser.py
  schemas.py
  vault.py
  static/
lovable-integration/
  cookieCoreClient.ts
  supabase/functions/cookie-core/index.ts
INSTRUCOES_CONTAINER_RAILWAY.md
PROMPT_LOVABLE.md
```

## Rotas

```text
GET    /health/live
GET    /v1/services
POST   /v1/services/:serviceId/launch
POST   /v1/launch/exchange

GET    /v1/admin/services
POST   /v1/admin/services
PUT    /v1/admin/services/:serviceId
GET    /v1/admin/services/:serviceId/users/:userId/profiles
POST   /v1/admin/services/:serviceId/users/:userId/profiles/import
DELETE /v1/admin/services/:serviceId/users/:userId/profiles/:profileId
```

As rotas `/remote/*` pertencem à sessão Playwright e não devem ser recriadas no
Lovable.

## Implantação

Siga [INSTRUCOES_CONTAINER_RAILWAY.md](INSTRUCOES_CONTAINER_RAILWAY.md).

## Regras invariantes

- O frontend nunca recebe valores de cookies.
- O administrador importa por uma Edge Function do sistema existente.
- O usuário comum nunca recebe a opção de importar.
- Consultas usam `user_id + service_id + profile_id`.
- Um `BrowserContext` nunca é reutilizado.
- O serviço Railway deve iniciar com uma réplica enquanto as sessões forem mantidas
  em memória.
- Não registre headers Authorization/Cookie, bodies de importação ou launch tokens.

Cookies protegidos por mecanismos anti-bot podem depender do IP e navegador que os
criou.
