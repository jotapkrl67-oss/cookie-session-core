# Cookie Session Core

Reverse proxy headless para ser conectado a um projeto **Lovable/Supabase existente**.
O Lovable continua responsável por login, usuários, permissões, layout e navegação.
Este container mantém os cookies originais no servidor e entrega ao navegador
somente um grant opaco, `HttpOnly`, do próprio proxy.

## O que está pronto

- API FastAPI autenticada com JWT do Supabase;
- compatibilidade com JWT assimétrico via JWKS e projetos legados HS256;
- autorização administrativa intermediada pela Edge Function do projeto existente;
- importação DevTools, JSON, Netscape e Cookie header;
- AES-256-GCM com chave derivada por usuário e serviço;
- token de lançamento com 30 segundos e consumo único;
- reverse proxy HTTP com cookies injetados exclusivamente no upstream;
- captura de `Set-Cookie` sem repassá-lo ao navegador;
- reescrita de redirects, HTML/CSS/JS/JSON, CSP e WebSockets;
- sincronização de cookies rotacionados no PostgreSQL;
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
  ├── reverse proxy HTTP/WebSocket
  └── cofre AES-256-GCM
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
  config.py
  core.py
  parser.py
  reverse_proxy.py
  schemas.py
  vault.py
lovable-integration/
  cookieCoreClient.ts
  supabase/functions/cookie-core/index.ts
INSTRUCOES_CONTAINER_RAILWAY.md
PROMPT_LOVABLE_SEM_PERFIS.md
```

## Rotas

```text
GET    /health/live
GET    /v1/services
POST   /v1/services/:serviceId/launch
GET    /v1/admin/services
POST   /v1/admin/services
PUT    /v1/admin/services/:serviceId
GET    /v1/admin/services/:serviceId/users/:userId/cookies
POST   /v1/admin/services/:serviceId/users/:userId/cookies/import
DELETE /v1/admin/services/:serviceId/users/:userId/cookies
```

O `launch_url` aponta diretamente para `/proxy/:serviceId/*`. O Lovable apenas o
abre em outra aba. O token é consumido uma vez, removido da URL por redirect `303`
e trocado por `__Secure-cookie_core_proxy`. Rotas `/proxy/*` não devem ser
recriadas no Lovable nem atravessar a Edge Function.

Ao atualizar uma instalação antiga com múltiplos perfis, a inicialização preserva
para cada usuário e serviço somente os cookies do perfil padrão — ou do mais
recentemente atualizado — e remove a estrutura de perfis. Grants e lançamentos
temporários anteriores ao deploy são invalidados.

## Implantação

Siga [INSTRUCOES_CONTAINER_RAILWAY.md](INSTRUCOES_CONTAINER_RAILWAY.md).

## Regras invariantes

- O frontend nunca recebe valores de cookies.
- O administrador importa por uma Edge Function do sistema existente.
- O usuário comum nunca recebe a opção de importar.
- Toda ferramenta habilitada aparece para todos os usuários autenticados.
- Existe somente um conjunto de cookies por `user_id + service_id`; não há perfis.
- O cookie interno do proxy nunca contém `user_id` ou cookies do site.
- Todo grant e todo cookie são novamente vinculados a `user_id + service_id`
  no banco antes de uma requisição upstream.
- Não registre headers Authorization/Cookie, bodies de importação ou launch tokens.

## Limites da reescrita

HTML, CSS e URLs absolutas em JavaScript/JSON são reescritos, e um adaptador em
runtime cobre `fetch`, XHR, EventSource e WebSocket. Aplicações que constroem URLs
por ofuscação, usam pinagem de origem, assinatura de URL, DRM ou service workers
podem exigir um adaptador específico. Cadastre todos os hosts legítimos usados
pelo serviço em `allowed_domains`.

Cookies protegidos por mecanismos anti-bot podem depender do IP e navegador que os
criou.
