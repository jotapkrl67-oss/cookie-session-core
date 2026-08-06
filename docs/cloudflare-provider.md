# Cloudflare Cookie Provider

## Arquitetura

O Cookie Session Core continua na VPS e mantém cookies de conta criptografados no
PostgreSQL. Um segundo serviço Railway executa Chromium somente quando o core
detecta que uma requisição foi bloqueada pela Cloudflare.

```text
Navegador do usuário
        │ grant opaco
        ▼
Cookie Session Core (VPS)
        │ cookies da conta + transporte curl_cffi
        │
        ├── resposta normal ───────────────► navegador
        │
        └── challenge Cloudflare confirmado
                    │
                    ▼
          CloudflareCookieCoordinator
                    │ single-flight por origem/porta/egress
                    ▼
          HttpCloudflareCookieProvider
                    │ POST /solve
                    ▼
          Playwright Service (Railway)
                    │ abre Chromium e espera clearance
                    ▼
          cookies + User-Agent + expiresAt
                    │
                    ▼
          store transitório por origem/porta/egress
                    │
                    ▼
          repetição da requisição original
```

Os cookies retornados pelo Playwright não são gravados no cofre individual do
usuário. Eles representam a sessão de transporte Cloudflare e ficam em memória,
por hostname, junto com o User-Agent que os originou. Cookies reais da conta
continuam no PostgreSQL.

O solver legado (CapSolver, AntiCaptcha, YesCaptcha, 2Captcha ou custom) permanece
disponível como fallback. Desabilitar o provider novo restaura o comportamento
anterior sem mudança de API.

## Contrato HTTP

Requisição:

```http
POST /solve HTTP/1.1
Authorization: Bearer <PLAYWRIGHT_SERVICE_TOKEN>
Content-Type: application/json

{"url":"https://app.example.com/protected"}
```

Resposta:

```json
{
  "cookies": [
    {
      "name": "cf_clearance",
      "value": "...",
      "domain": ".example.com",
      "path": "/",
      "expires": 1800000000,
      "httpOnly": true,
      "secure": true,
      "sameSite": "None"
    }
  ],
  "userAgent": "Mozilla/5.0 ...",
  "expiresAt": 1800000000
}
```

`expiresAt` e `cookies[].expires` usam Unix epoch em segundos. O cliente também
aceita milissegundos e os normaliza. Cookies de sessão podem omitir a expiração ou
usar `-1`.

## Sequência completa

1. O reverse proxy carrega e descriptografa os cookies do usuário.
2. O `BrowserLikeClient` mescla uma sessão Cloudflare ainda válida, se existir.
3. A requisição é enviada com `curl_cffi` e TLS impersonation.
4. A resposta é classificada de forma centralizada. `429` é sempre rate limit e
   respeita `Retry-After`; `403`/`503` só iniciam solve com evidência de challenge.
5. Se `CF_AUTO_REFRESH=true`, o coordinator consulta o provider.
6. Somente uma resolução pode executar por origem, porta e identidade de egress.
   Origens diferentes progridem em paralelo; waiters compartilham resultado/erro.
7. O Railway abre um Chromium novo, navega até a URL e aguarda `cf_clearance`.
8. Cookies e User-Agent são capturados. Página, contexto e navegador são fechados
   em blocos `finally`.
9. O core valida nomes, valores, domínios, paths, expirações e User-Agent antes de
   publicar a sessão no store.
10. Cookies são mesclados por nome, domínio e path; o User-Agent é aplicado só
    enquanto a sessão transitória correspondente está ativa.
11. A requisição só é repetida quando é segura: método seguro, sem body, ou com
    `Idempotency-Key`, e dentro do limite configurado de buffering.
12. Se continuar bloqueada, o fluxo normal de retry e o solver legado ainda podem
    ser usados.

## Subir o Playwright Service no Railway

Crie um segundo serviço no mesmo projeto Railway ou em outro projeto:

1. Selecione este repositório.
2. Configure **Root Directory** como `playwright-service`.
3. O Railway encontrará `playwright-service/railway.toml` e usará o Dockerfile.
4. Gere um token aleatório com pelo menos 32 caracteres:

   ```bash
   openssl rand -hex 32
   ```

5. Configure no serviço Railway:

   ```dotenv
   PLAYWRIGHT_SERVICE_TOKEN=<token-gerado>
   SOLVE_TIMEOUT_SECONDS=120
   NAVIGATION_TIMEOUT_SECONDS=90
   MAX_CONCURRENT_BROWSERS=1
   MAX_QUEUE_SIZE=20
   QUEUE_TIMEOUT_SECONDS=30
   MAX_REQUEST_BODY_BYTES=4096
   MAX_RESPONSE_COOKIES=100
   MAX_COOKIE_VALUE_BYTES=8192
   MAX_REDIRECTS=10
   ALLOWED_DESTINATION_PORTS=80,443
   REQUIRE_HTTPS_DESTINATION=false
   SHUTDOWN_TIMEOUT_SECONDS=20
   ```

6. Gere um domínio público HTTPS para o serviço.
7. Confirme `GET https://<dominio>/health/live` e `/health/ready`.

O container instala Chromium durante o build. Cada solve cria e fecha um browser
completo; o processo Playwright permanece inicializado apenas para reduzir o custo
de bootstrap da biblioteca.

### Egress pela VPS

A Cloudflare liga clearance ao visitante/dispositivo e pode invalidar cookies
reutilizados por outra máquina ou IP. Para aproximar o IP de emissão do IP usado
pelo core, exponha na VPS um forward proxy autenticado e configure no Railway:

```dotenv
BROWSER_PROXY_SERVER=http://proxy-vps.example.com:3128
BROWSER_PROXY_USERNAME=<usuario>
BROWSER_PROXY_PASSWORD=<senha>
```

Restrinja esse proxy por autenticação, firewall e destino. Mesmo com o mesmo IP e
User-Agent, proteções fortes podem reconhecer que Chromium e `curl_cffi` são
dispositivos diferentes; essa arquitetura não garante bypass de toda configuração
Cloudflare.

## Configurar o Cookie Session Core na VPS

Use o mesmo token do Railway:

```dotenv
PLAYWRIGHT_SERVICE_URL=https://playwright-service.up.railway.app
PLAYWRIGHT_SERVICE_TOKEN=<token-gerado>
CF_AUTO_REFRESH=true
```

Se o Playwright usa `BROWSER_PROXY_*`, o core também precisa usar o mesmo proxy
para HTTP e WebSocket:

```dotenv
UPSTREAM_PROXY_URL=http://proxy-vps.example.com:3128
UPSTREAM_PROXY_USERNAME=<usuario>
UPSTREAM_PROXY_PASSWORD=<senha>
```

Credenciais embutidas na URL são rejeitadas; mantenha-as nos campos separados.

Configurações existentes reutilizadas:

```dotenv
CF_SOLVER_TIMEOUT_SECONDS=120
CF_SOLVER_MAX_RETRIES=2
CF_CLEARANCE_EXPIRY_SKEW_SECONDS=15
CF_CLEARANCE_DEFAULT_TTL_SECONDS=2700
CF_CLEARANCE_MAX_TTL_SECONDS=86400
CF_SOLVE_COOLDOWN_SECONDS=30
CF_SOLVE_NEGATIVE_CACHE_SECONDS=10
CF_CLEARANCE_STORE_MAX_ENTRIES=1000
CF_CHALLENGE_BODY_INSPECTION_LIMIT_BYTES=262144
CF_REQUEST_REPLAY_BUFFER_LIMIT_BYTES=2000000
```

`PLAYWRIGHT_SERVICE_URL` deve ser somente a origem, sem `/solve`, path, query ou
credenciais. O core acrescenta `/solve` automaticamente. O token deve ter ao menos
32 caracteres.

Para desabilitar rapidamente sem remover credenciais:

```dotenv
CF_AUTO_REFRESH=false
```

## Como testar

### Serviço Playwright isoladamente

```bash
curl -i https://playwright-service.up.railway.app/health/live

curl -i \
  -H "Authorization: Bearer $PLAYWRIGHT_SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"url":"https://site-protegido.example/"}' \
  https://playwright-service.up.railway.app/solve
```

Nunca coloque o token diretamente no histórico do shell em ambientes
compartilhados.

Testes do microserviço:

```bash
uv run --project playwright-service --extra dev pytest -q playwright-service/tests
```

### Core

```bash
uv run pytest -q
uv run ruff check src tests
```

Depois, faça uma requisição real pelo proxy e consulte:

```text
GET /v1/admin/cf/status
GET /v1/admin/cf/clearance
GET /metrics
```

Os logs informam domínio, resultado e tipo de erro, mas nunca registram cookies,
token do provider ou headers de autenticação.

## Possíveis erros

| Sintoma | Causa provável | Ação |
| --- | --- | --- |
| Core não chama `/solve` | Provider incompleto ou `CF_AUTO_REFRESH=false` | Verifique `/v1/admin/cf/status` e as três variáveis |
| `401 Invalid service token` | Tokens diferentes | Atualize ambos os serviços com o mesmo token |
| `400 Private destinations` | URL aponta para IP privado, loopback ou DNS privado | Use somente um hostname público permitido |
| `504 Browser navigation timed out` | Site lento, proxy indisponível ou challenge não concluiu | Verifique egress e aumente os timeouts com cautela |
| `504 Cloudflare did not issue cf_clearance` | Challenge interativo, CAPTCHA ou headless bloqueado | Teste o site manualmente e revise a política Cloudflare |
| Cookie retornado mas novo `403` | Cookie ligado ao IP/dispositivo do Railway | Use egress pela VPS; considere resolver junto ao core |
| Muitos `429` | Rate limit, não challenge | Respeite `Retry-After`; clearance não ignora rate limiting |
| User-Agent correto mas bloqueio persiste | TLS/client hints/fingerprint não correspondem ao Chromium | Alinhe impersonation ou mantenha a requisição no mesmo browser |
| Sessões somem após restart | Store Cloudflare é intencionalmente volátil | O primeiro novo challenge fará renovação automática |

## Retry e backoff

- O core repete imediatamente uma vez após publicar cookies novos.
- O loop existente usa backoff exponencial com jitter para `429` e falhas
  transitórias.
- `Retry-After` do upstream tem prioridade quando presente.
- O coordinator não executa dois browsers para a mesma chave; o serviço também
  impõe semaphore e fila limitada independentemente do core.
- Waiters do mesmo hostname compartilham sucesso ou erro da mesma resolução.
- O solver legado pode ser configurado como fallback, sem substituir o provider.
- Não faça retry ilimitado: challenges persistentes geralmente indicam vínculo de
  IP/fingerprint, não instabilidade temporária.

## Renovação automática

A sessão é considerada válida até `expiresAt`, com uma margem de 15 segundos. Se
o campo estiver ausente, o core usa primeiro a expiração de `cf_clearance`, depois
a menor expiração futura retornada e, por último, o TTL padrão de 2700 segundos.

A expiração local não é a única causa de renovação. Um challenge confirmado pode
invalidar a sessão; cooldown e negative cache evitam tempestades de solves.

O store é limpo naturalmente em restart. Isso evita persistir cookies de
fingerprint em disco e garante que um deploy não reutilize indefinidamente uma
sessão emitida para um browser anterior.

## Segurança operacional

- Use HTTPS entre VPS e Railway.
- Rotacione `PLAYWRIGHT_SERVICE_TOKEN` como um segredo de máquina.
- Não exponha `/solve` sem Bearer authentication.
- O serviço rejeita destinos literais ou resolvidos como privados, loopback,
  link-local, multicast, CGNAT ou reservados, revalida requests/redirects e
  bloqueia downgrade HTTPS e portas fora da allowlist.
- Restrinja acesso de rede ao forward proxy opcional.
- Não envie cookies de conta ao Playwright Service; ele deve obter somente os
  cookies gerados durante a passagem pela Cloudflare.
- Use o provider apenas em sites para os quais você tem autorização de acesso e
  automação.

## Trust boundaries e limitações

O core confia no Playwright Service apenas para produzir uma resposta candidata;
domínio, path, flags, tamanhos, expiração e User-Agent são revalidados antes do
uso. O serviço nunca recebe cookies da conta nem funciona como proxy arbitrário.
O store é volátil e separado do PostgreSQL.

A interceptação revalida DNS antes de cada request do browser, inclusive
redirects. O Playwright não oferece pinning confiável do IP efetivamente conectado;
portanto existe uma janela residual entre validação e conexão. Restrinja também o
egress do container por firewall/política de rede para defesa em profundidade.

Cloudflare pode correlacionar IP, fingerprint TLS/HTTP2, Client Hints, estado
JavaScript e comportamento. Um cookie emitido pelo Chromium pode falhar no
`curl_cffi`; não há garantia de reutilização entre fingerprints. Quando a
coerência for indispensável, a operação protegida precisará permanecer no mesmo
contexto autorizado do browser. O serviço não resolve CAPTCHA.

## Rotação, rollback e recursos

Para rotação sem interrupção, defina `PLAYWRIGHT_SERVICE_TOKEN_NEXT` no Railway,
atualize o token do core, promova-o a `PLAYWRIGHT_SERVICE_TOKEN` e remova o next.
Nunca registre os valores. Para rollback imediato, defina `CF_AUTO_REFRESH=false`;
o solver legado continua disponível conforme sua configuração anterior.

Chromium consome memória significativa. Comece com uma instância de pelo menos
1 GB e `MAX_CONCURRENT_BROWSERS=1`; ajuste com métricas reais de memória e fila.
Consulte [runbook-cloudflare.md](runbook-cloudflare.md) para incidentes.
