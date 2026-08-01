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
- suporte a widgets legítimos de Cloudflare Turnstile, reCAPTCHA, hCaptcha e
  desafios que carregam recursos dinamicamente;
- relay de Cloudflare Challenge Pages quando publicado no hostname protegido e
  diagnóstico seguro quando a topologia é incompatível;
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

Cookies protegidos por mecanismos anti-bot podem depender do IP e navegador que os
criou.

### Cloudflare Managed Challenge

O proxy detecta a resposta oficial `cf-mitigated: challenge`, guarda qualquer
`Set-Cookie` somente no cofre e trata o HTML do desafio separadamente, sem injetar
o adaptador normal ou substituir a CSP/nonces da Cloudflare. URLs internas de
`/cdn-cgi/challenge-platform/` permanecem no mesmo fluxo do proxy, de modo que a
emissão e a resolução saem pelo mesmo IP.

O modo recomendado para aplicações desse tipo é cadastrar um `proxy_hostname`
dedicado por serviço, por exemplo `chat.exemplo.com`. Nesse modo os caminhos são
preservados na raiz (`/cdn/assets/*`, `/cdn-cgi/*`, APIs e navegação), todo o ciclo
do challenge continua saindo pelo IP do container e o relay é habilitado. Hosts
secundários permitidos continuam disponíveis sob `/_host/<hostname>/*`.

No modo antigo com prefixo `/proxy/:serviceId`, o relay só é habilitado quando
`PUBLIC_BASE_URL` e upstream têm o mesmo hostname/porta. Caso contrário, retorna
`502` com `X-Cookie-Core-Upstream-Challenge` e `X-Cookie-Core-Cf-Ray`. Embora o
modo transparente reproduza a topologia usada por proxies comerciais, provedores
anti-bot podem mudar seus sinais e não existe garantia universal de passagem.

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
