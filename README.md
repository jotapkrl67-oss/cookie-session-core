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
- recuperação genérica de navegações, APIs, workers e assets que escapam de
  `/proxy/:serviceId`, com redirect canônico para documentos;
- isolamento por serviço de cookies visíveis ao JavaScript, `localStorage`,
  `sessionStorage`, IndexedDB e BroadcastChannel no modo por prefixo;
- reescrita de manifests, `@import`, atributos sem aspas, meta refresh, `srcset`,
  service workers e APIs DOM criadas dinamicamente;
- suporte a widgets legítimos de Cloudflare Turnstile, reCAPTCHA, hCaptcha e
  desafios que carregam recursos dinamicamente;
- diagnóstico seguro de Cloudflare Challenge Pages quando a topologia é
  incompatível;
- sincronização de cookies rotacionados no PostgreSQL;
- renovação automática de cookies Cloudflare por um microserviço Playwright
  isolado, com User-Agent vinculado e single-flight;
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
PROMPT_LOVABLE.md
```

## Rotas

```text
GET    /health/live
GET    /metrics
GET    /v1/services
POST   /v1/services/:serviceId/launch
GET    /v1/admin/services
POST   /v1/admin/services
PUT    /v1/admin/services/:serviceId
GET    /v1/admin/services/:serviceId/users/:userId/cookies
POST   /v1/admin/services/:serviceId/users/:userId/cookies/import
DELETE /v1/admin/services/:serviceId/users/:userId/cookies
GET    /v1/admin/services/:serviceId/users/:userId/localstorage
POST   /v1/admin/services/:serviceId/users/:userId/localstorage/import
DELETE /v1/admin/services/:serviceId/users/:userId/localstorage
```

A importação de `localStorage` recebe `{ "items": "{\"chave\":\"valor\"}" }`.
Ela substitui somente o conjunto de `localStorage`, sem alterar cookies. Os
valores permanecem criptografados no banco, são carregados antes dos scripts da
ferramenta e alterações feitas pela aplicação são sincronizadas de volta. A API
administrativa lista apenas chaves e datas, nunca valores.

`/metrics` expõe counters Prometheus em memória e pode ser desabilitado com
`METRICS_ENABLED=false`. Para fallback de solver em cascata, configure
`CF_SOLVER_PROVIDERS=yescaptcha,custom,capsolver`; chaves distintas podem ser
fornecidas como JSON em `CF_SOLVER_API_KEYS` e timeouts por provider em
`CF_SOLVER_PROVIDER_TIMEOUTS`. `CF_SOLVER_PROVIDER` e `CF_SOLVER_API_KEY`
continuam compatíveis para instalações com um único provider.

Por padrão, o `launch_url` aponta para `/proxy/:serviceId/*`. Quando o serviço tem
`proxy_hostname`, ele aponta para `https://<proxy_hostname>/*`, preservando os
caminhos originais como um proxy transparente. O Lovable apenas abre a URL em
outra aba. O token é consumido uma vez, removido por redirect `303` e trocado por
`__Secure-cookie_core_proxy`.

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

Para máxima compatibilidade, use um `proxy_hostname` dedicado para cada serviço.
O modo `/proxy/:serviceId` possui isolamento e fallback de rotas, mas continua
compartilhando a origem pública da API; aplicações que comparam rigidamente
`location.origin` funcionam melhor em um hostname dedicado.

Nenhum reverse proxy pode prometer compatibilidade literal com todos os sites.
Continuam dependendo de configuração externa ou da origem real:

- Google OAuth/GSI e SDKs equivalentes exigem que o hostname público esteja nos
  *Authorized JavaScript origins* do cliente OAuth;
- DRM, WebAuthn/passkeys, pinagem de origem, certificados de cliente e URLs
  assinadas vinculadas ao hostname podem recusar uma origem intermediária;
- Cloudflare Managed Challenge não pode emitir clearance válido para um vanity
  hostname diferente do hostname protegido;
- service workers ou bundles ofuscados que removem `Referer` podem exigir um
  adaptador específico do produto.

Avisos de preload não utilizado e telemetria RUM não impedem a aplicação. O
endpoint opcional `/cdn-cgi/rum` é reconhecido localmente para não produzir 404.
Scripts como `passwordCapture.js` não fazem parte deste projeto; se aparecerem no
console, revise extensões e scripts injetados no navegador.

## Provider Playwright para Cloudflare

Para usar o microserviço separado, configure `PLAYWRIGHT_SERVICE_URL`,
`PLAYWRIGHT_SERVICE_TOKEN` e `CF_AUTO_REFRESH=true`. A arquitetura, implantação
no Railway, testes, renovação e limitações de fingerprint estão documentados em
[docs/cloudflare-provider.md](docs/cloudflare-provider.md).

Cookies protegidos por mecanismos anti-bot podem depender do IP e navegador que os
criou.

### Cloudflare Managed Challenge

O proxy detecta a resposta oficial `cf-mitigated: challenge` e guarda qualquer
`Set-Cookie` somente no cofre. Uma Challenge Page só pode ser retransmitida quando
o endereço público tem exatamente a mesma origem HTTPS do upstream. Preservar os
caminhos em um `proxy_hostname` dedicado não basta: `chat.exemplo.com` continua
sendo uma origem diferente de `chatgpt.com`, e os tokens/cookies do desafio não
podem ser validados nesse outro domínio.

Quando a origem não coincide — tanto no modo `/proxy/:serviceId` quanto no modo
transparente — a resposta é `502`, com `X-Cookie-Core-Upstream-Challenge` e
`X-Cookie-Core-Cf-Ray`, em vez de deixar o navegador preso em uma verificação que
não pode terminar.

Se o serviço usa `allowed_cookie_names`, inclua também os cookies exigidos pela
proteção (por exemplo, `cf_clearance` e `__cf_bm`). Com a lista vazia, cookies
válidos dos domínios permitidos são capturados normalmente.

Para um upstream sob seu controle, a solução é feita no Cloudflare WAF/Access:

- use um IP de saída estático para o container e crie uma regra WAF restrita que
  não aplique Challenge a esse IP; ou
- proteja a comunicação proxy/upstream com Cloudflare Access e credenciais de
  serviço (máquina-a-máquina); ou
- use Turnstile com pre-clearance no hostname real quando o navegador acessa esse
  mesmo hostname diretamente.

Widgets Turnstile embutidos e equivalentes continuam funcionando em domínio
separado: a CSP permite HTTPS para scripts, imagens, frames, conexões e workers, e
o adaptador cobre `fetch`, XHR, `sendBeacon`, EventSource, WebSocket, Worker,
SharedWorker, atributos DOM dinâmicos e navegação por History API. O hostname do
proxy ainda precisa estar autorizado na configuração do próprio widget. Cookies
criados pelo JavaScript da página são isolados por serviço no navegador e só são
enviados ao upstream correspondente; cookies recebidos do upstream continuam
exclusivamente no cofre.
