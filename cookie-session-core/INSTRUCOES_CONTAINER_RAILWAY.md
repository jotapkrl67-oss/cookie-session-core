# Deploy de produção no Railway

## 1. Serviços

Crie um serviço Railway a partir deste diretório e conecte um PostgreSQL. O
`Dockerfile` executa a aplicação como usuário sem privilégios e o
`railway.toml` usa `/health/live` como health check.

Configure pelo menos:

```text
DATABASE_URL=${{Postgres.DATABASE_URL}}
SUPABASE_URL=https://SEU-PROJETO.supabase.co
SUPABASE_PUBLISHABLE_KEY=...
SUPABASE_JWT_AUDIENCE=authenticated
COOKIE_VAULT_KEY_BASE64=...
LAUNCH_TOKEN_PEPPER_BASE64=...
ADMIN_PROXY_SECRET=...
PUBLIC_BASE_URL=https://api.seu-dominio.com
ALLOWED_ORIGINS=https://seu-app-lovable.com
SECURE_COOKIES=true
```

Gere os três segredos com valores diferentes:

```bash
openssl rand -base64 32
openssl rand -base64 32
openssl rand -hex 32
```

O primeiro valor é `COOKIE_VAULT_KEY_BASE64`, o segundo é
`LAUNCH_TOKEN_PEPPER_BASE64` e o terceiro é `ADMIN_PROXY_SECRET`. Trocar a chave
do cofre depois de importar cookies torna os valores anteriores indecifráveis.

## 2. Domínios

Adicione `api.seu-dominio.com` como domínio do serviço Railway. Para máxima
compatibilidade, crie também um subdomínio dedicado por produto, por exemplo
`dreamface.seu-dominio.com`, e grave esse hostname no campo `proxy_hostname` do
serviço.

Se usar Cloudflare na frente do Railway:

- use SSL/TLS **Full (strict)**;
- não faça cache de `/proxy/*`, `/v1/*` ou respostas com `Cache-Control: no-store`;
- encaminhe `Host`/`X-Forwarded-Host` originais;
- não aplique Managed Challenge nos hostnames do proxy;
- mantenha WebSockets habilitados.

Depois de alterar `proxy_hostname`, aguarde até 30 segundos pelo cache interno de
resolução ou reinicie o container.

## 3. Supabase/Lovable

Implante `lovable-integration/supabase/functions/cookie-core/index.ts` como Edge
Function `cookie-core` e configure nela:

```text
COOKIE_CORE_API_URL=https://api.seu-dominio.com
COOKIE_CORE_ADMIN_SECRET=<mesmo ADMIN_PROXY_SECRET>
COOKIE_CORE_ADMIN_ROLE=admin
LOVABLE_APP_ORIGIN=https://seu-app-lovable.com
```

Use `cookieCoreClient.ts` com o cliente Supabase já existente. Não exponha
`ADMIN_PROXY_SECRET`, chaves de solver ou valores de cookies no frontend.

## 4. Cadastro de cada produto

- `upstream_url`: URL HTTPS inicial real;
- `allowed_domains`: domínio principal e todos os hosts de API, CDN, autenticação
  e WebSocket usados pelo produto;
- `allowed_paths`: use `/` para compatibilidade geral ou restrinja somente quando
  todos os endpoints necessários forem conhecidos;
- `allowed_cookie_names`: deixe vazio para aceitar todos os cookies válidos dos
  domínios permitidos;
- `proxy_hostname`: subdomínio dedicado recomendado.

Google GSI/OAuth só funciona quando o proprietário do OAuth Client adiciona o
hostname público em **Authorized JavaScript origins**. Um proxy não consegue
ignorar essa validação de segurança.

## 5. Verificação

```bash
curl -fsS https://api.seu-dominio.com/health/live
uv run --extra dev pytest -q
uv run --extra dev ruff check src tests
```

Após cada deploy que altera cookies do proxy, gere um novo link de lançamento e
faça um hard refresh. URLs de `/cdn-cgi/challenge-platform/.../oneshot/...` são
temporárias e não devem ser reutilizadas em `curl` depois de expirarem.
