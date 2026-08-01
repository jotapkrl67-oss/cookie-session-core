# Instruções humanas: Cookie Session Core no Railway

Este guia parte do princípio de que já existe:

- um projeto Lovable funcionando;
- Supabase Auth configurado;
- usuários reais;
- uma regra de administrador no sistema;
- um repositório GitHub do projeto.

Não crie outro frontend, outro login ou outra tabela de usuários.

## 1. O que será implantado

Somente a pasta `cookie-session-core` vai rodar no Railway. O projeto Lovable
continua onde já está.

```text
Lovable atual → Edge Function atualizada → Railway → Supabase
```

O Railway executará FastAPI e o reverse proxy HTTP/WebSocket em um único container.

## 2. Pré-requisitos

Tenha acesso a:

1. repositório GitHub do projeto;
2. painel do Supabase;
3. Supabase CLI ou SQL Editor;
4. conta Railway;
5. configuração que informa quem é administrador no projeto atual.

Use um repositório privado. Nunca faça commit de `.env`, cookies, tokens ou chaves.

## 3. Adicionar a pasta ao projeto existente

Coloque `cookie-session-core` na raiz do mesmo repositório:

```text
meu-projeto-lovable/
  src/
  supabase/
  cookie-session-core/
```

Não mova o frontend para dentro dessa pasta.

## 4. Aplicar a migration no Supabase

### Alternativa para projetos que usam Lovable Cloud

Se o projeto não oferece acesso ao painel do Supabase, adicione um serviço
PostgreSQL no mesmo projeto Railway e use:

```text
DATABASE_URL=${{Postgres.DATABASE_URL}}
```

Nesta modalidade não execute o `schema.sql` manualmente. O Cookie Session Core
cria e atualiza de forma idempotente as próprias tabelas prefixadas ao iniciar.
O banco do Railway guarda somente os dados internos do Cookie Core; usuários e
login continuam no Lovable Cloud.

Os valores públicos `SUPABASE_URL` e `SUPABASE_PUBLISHABLE_KEY` podem ser obtidos
das variáveis `VITE_SUPABASE_URL` e `VITE_SUPABASE_PUBLISHABLE_KEY` do projeto
Lovable. Nunca use uma chave `service_role` no frontend.

### Projetos com acesso ao Supabase

O arquivo é:

```text
cookie-session-core/sql/schema.sql
```

Ele cria somente tabelas prefixadas:

```text
cookie_core_services
cookie_core_stored_cookies
cookie_core_launch_tokens
cookie_core_proxy_grants
cookie_core_audit_logs
```

Isso reduz a chance de colisão com tabelas do Lovable existente.

Opção A — SQL Editor:

1. abra Supabase Dashboard;
2. entre em SQL Editor;
3. crie uma nova query;
4. cole `schema.sql`;
5. revise o projeto selecionado;
6. execute uma vez.

Opção B — migration do repositório:

1. copie o conteúdo para uma nova migration em `supabase/migrations`;
2. preserve a ordem cronológica usada no projeto;
3. execute `supabase db push`.

Depois, confirme que `anon` e `authenticated` não conseguem acessar diretamente
essas tabelas. O frontend deve usar a Edge Function.

## 5. Gerar segredos

Execute localmente três vezes:

```bash
openssl rand -base64 48
```

Use os resultados como:

```text
COOKIE_VAULT_KEY_BASE64
LAUNCH_TOKEN_PEPPER_BASE64
ADMIN_PROXY_SECRET
```

O terceiro valor também será cadastrado no Supabase como
`COOKIE_CORE_ADMIN_SECRET`. Os dois nomes devem possuir exatamente o mesmo valor.

Não reutilize senha do banco, JWT secret ou chave do Supabase.

## 6. Obter dados de autenticação e banco

Separe:

```text
DATABASE_URL
SUPABASE_URL
SUPABASE_PUBLISHABLE_KEY
```

Use uma connection string PostgreSQL server-side com SSL. Se usar o pooler do
Supabase, escolha um modo compatível com conexões persistentes do `asyncpg`.
Nunca coloque `DATABASE_URL` no Lovable ou em variável `VITE_`.

Se estiver usando o PostgreSQL do Railway, `DATABASE_URL` deve ser uma referência
privada a `${{Postgres.DATABASE_URL}}`, não uma URL copiada para o frontend.

## 7. Criar o serviço no Railway

1. entre no Railway;
2. crie um projeto vazio;
3. escolha `Deploy from GitHub repo`;
4. selecione o repositório privado;
5. nas configurações do serviço, defina Root Directory como:

```text
/cookie-session-core
```

6. confirme que o Railway detectou `Dockerfile`;
7. mantenha uma única réplica;
8. gere um domínio público em Networking.

O `railway.toml` já configura `/health/live`.
O processo escuta a variável `PORT` fornecida pelo Railway.

Configure o domínio customizado que receberá as sessões, por exemplo
`servico.jbtools.site`, apontando-o para este serviço Railway.

## 8. Configurar variáveis no Railway

Abra Variables e configure:

```env
DATABASE_URL=...
SUPABASE_URL=https://SEU_PROJETO.supabase.co
SUPABASE_PUBLISHABLE_KEY=...
SUPABASE_JWT_AUDIENCE=authenticated

COOKIE_VAULT_KEY_BASE64=...
LAUNCH_TOKEN_PEPPER_BASE64=...
ADMIN_PROXY_SECRET=...

PUBLIC_BASE_URL=https://servico.jbtools.site
ALLOWED_ORIGINS=https://SEU_PROJETO_LOVABLE

PROXY_GRANT_TTL_SECONDS=1800
PROXY_TIMEOUT_SECONDS=60
PROXY_MAX_REWRITE_BYTES=10000000
SECURE_COOKIES=true
```

Use o domínio Railway gerado no valor de `PUBLIC_BASE_URL`. Não coloque `/` ou
caminho adicional no final.

Salve e faça redeploy.

## 9. Confirmar o container

Abra:

```text
https://SEU_SERVICO.up.railway.app/health/live
```

Resultado esperado:

```json
{
  "status": "ok",
  "database": true,
  "proxy": true
}
```

Se `database` falhar, revise `DATABASE_URL`, senha, SSL e rede.
Se `proxy` não aparecer, confirme que o deploy usa a versão atual desta pasta.

O Railway usa o Dockerfile quando ele está na raiz configurada e usa `PORT` para
health checks. Consulte:

- https://docs.railway.com/builds/dockerfiles
- https://docs.railway.com/deployments/healthchecks

## 10. Instalar a Edge Function no Supabase existente

Copie:

```text
cookie-session-core/lovable-integration/supabase/functions/cookie-core
```

para:

```text
supabase/functions/cookie-core
```

Se a pasta `supabase/functions` já existe, adicione somente `cookie-core`; não
sobrescreva outras funções.

### Adaptar a verificação de administrador

Abra `index.ts` e localize:

```ts
const role = data.user.app_metadata?.role;
```

Se o projeto já usa `app_metadata.role`, não altere.

Se o projeto guarda permissões em uma tabela, substitua somente esse trecho pela
mesma consulta server-side já utilizada nas outras Edge Functions. Não consulte
`user_metadata` para autorização, pois o usuário pode alterá-la.

O resultado precisa ser booleano e derivado do usuário validado por
`supabase.auth.getUser()`.

## 11. Configurar secrets da Edge Function

No diretório do projeto:

```bash
supabase secrets set \
  COOKIE_CORE_API_URL=https://SEU_SERVICO.up.railway.app \
  COOKIE_CORE_ADMIN_SECRET=O_MESMO_VALOR_DE_ADMIN_PROXY_SECRET \
  LOVABLE_APP_ORIGIN=https://SEU_PROJETO_LOVABLE \
  COOKIE_CORE_ADMIN_ROLE=admin
```

O Supabase já disponibiliza `SUPABASE_URL` e uma chave do projeto no ambiente das
funções. Se o projeto usa o novo nome de publishable key, adapte no `index.ts` a
linha que cria o cliente.

Faça deploy:

```bash
supabase functions deploy cookie-core
```

Mantenha autenticação JWT habilitada para essa função.

Referências oficiais:

- https://supabase.com/docs/guides/functions/auth
- https://supabase.com/docs/guides/functions/auth-headers

## 12. Integrar no Lovable existente

Use:

```text
cookie-session-core/lovable-integration/cookieCoreClient.ts
```

Não crie outro cliente Supabase. Passe o cliente que o projeto já usa.

Exemplo:

```ts
const result = await cookieCoreRequest(
  supabase,
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY,
  "/v1/services",
  { method: "GET" },
);
```

Se o projeto ainda usa `VITE_SUPABASE_ANON_KEY`, passe essa chave pública já
existente. Chaves públicas Supabase podem estar no frontend; os segredos do Cookie
Core não podem.

### Área administrativa existente

Adicione à administração atual:

1. criar/editar serviço;
2. escolher usuário existente;
3. escolher serviço;
4. colar cookies;
5. salvar;
6. listar metadados;
7. remover os cookies do usuário e ferramenta.

Não mostre valor, prefixo, sufixo ou botão de copiar cookie.

### Área normal existente

1. chame `GET /v1/services`;
2. use os cards/lista atuais;
3. ao clicar, chame `POST /v1/services/:id/launch`;
4. abra `launch_url` em outra aba.

O serviço abre em outra aba; fechar essa aba devolve o usuário ao Lovable que já
permaneceu aberto.

## 13. Teste seguro

Primeiro teste com valores falsos e um domínio controlado. Não use cookies reais
em código, logs ou screenshots.

Valide:

1. usuário comum recebe 403 em rotas administrativas;
2. administrador consegue criar serviço;
3. administrador importa cookie falso;
4. todos os usuários autenticados listam a ferramenta publicada;
5. cada usuário recebe somente seu próprio conjunto de cookies;
6. launch token abre uma vez;
7. repetir o token falha;
8. o navegador recebe somente `__Secure-cookie_core_proxy`, nunca `Set-Cookie`
   do upstream;
9. redirects e WebSockets permanecem dentro de `/proxy/:serviceId/`;
9. logs não contêm body, Authorization ou cookies.

Somente depois faça um teste manual com um usuário que tenha cookies configurados.

## 14. Operação

- mantenha uma réplica inicialmente;
- o processo Uvicorn deve continuar com `--workers 1`;
- cada processo teria memória de sessões diferente;
- antes de escalar horizontalmente, mova o registro de sessão para infraestrutura
  compartilhada ou use roteamento persistente;
- configure alertas de memória e reinício;
- faça backup do banco e das chaves em secret manager;
- sem `COOKIE_VAULT_KEY_BASE64`, cookies existentes não podem ser recuperados;
- rotacione cookies que tenham sido enviados por chat, e-mail ou log.

## 15. Limitações

Cookies de Cloudflare e mecanismos anti-bot podem estar vinculados ao navegador,
IP ou dispositivo original. O container não tenta contornar isso.

O sistema deve ser usado apenas com contas e serviços cuja intermediação seja
autorizada. Para serviços com OAuth/OIDC oficial, prefira a integração oficial.

## Checklist final

- [ ] Migration aplicada no Supabase correto
- [ ] Railway usando Root Directory `/cookie-session-core`
- [ ] Uma réplica e um worker
- [ ] Health retorna database/browser true
- [ ] Segredos diferentes e fora do Git
- [ ] Edge Function implantada
- [ ] Regra de admin adaptada ao projeto existente
- [ ] Cliente atual do Supabase reutilizado
- [ ] Layout Lovable existente preservado
- [ ] Usuário comum sem controles de cookies
- [ ] Teste de isolamento entre dois usuários aprovado
