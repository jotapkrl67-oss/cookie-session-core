# Prompt único para o Lovable — integração segura com Cookie Session Core

Disponibilize ao Lovable estes dois arquivos como referência:

- `lovable-integration/cookieCoreClient.ts`
- `lovable-integration/supabase/functions/cookie-core/index.ts`

Depois envie o texto abaixo no chat do projeto Lovable:

```text
Atualize o projeto Lovable EXISTENTE para integrar, com segurança e sem criar uma
segunda aplicação, o Cookie Session Core implantado no Railway.

Faça alterações reais no projeto e publique a Edge Function ao final. Antes de
editar, inspecione a autenticação, o cliente Supabase, a regra administrativa,
as rotas, os componentes e o design existentes. Reutilize esses mecanismos e
preserve a identidade visual atual.

OBJETIVO E LIMITES

- O Lovable continua responsável por login, usuários, administração e interface.
- A Edge Function `cookie-core` valida a sessão Supabase e encaminha somente as
  rotas de controle explicitamente permitidas para o Railway.
- O Railway mantém o cofre criptografado e devolve uma `launch_url` temporária.
- O frontend apenas abre a `launch_url`; não tenta fazer proxy da ferramenta.
- Não crie outro login, outro cliente Supabase, outra tabela de usuários ou
  outro sistema de permissões.
- Não altere o backend Railway a partir do Lovable.

NÃO CONTORNAR PROTEÇÕES DE TERCEIROS

- Não implemente ou integre solver de Cloudflare, CAPTCHA ou Turnstile.
- Não use CapSolver, AntiCaptcha, YesCaptcha, 2Captcha, FlareSolverr ou serviço
  equivalente.
- Não crie interface, rota ou secret para `cf_clearance`.
- Não capture, aceite, cole, envie, exponha ou reutilize `cf_clearance`.
- Não imite User-Agent, TLS, JA3, headers `sec-ch-*` ou sinais de navegador.
- Não tente repetir automaticamente uma Challenge Page e não carregue o proxy
  em iframe, canvas, webview ou navegador automatizado.
- Não apresente a integração como compatível com qualquer site HTTPS.
- Remova textos ou presets que prometam funcionamento universal ou passagem por
  proteções anti-bot.
- Quando uma ferramenta for incompatível por Challenge Page, mostre uma mensagem
  honesta de indisponibilidade. Não mostre instruções para burlar a proteção.

Para integrações com serviços externos que ofereçam API, OAuth, SSO ou plano
corporativo, prefira e recomende o mecanismo oficial. Não apresente
compartilhamento de cookie de sessão como substituto de uma integração oficial.

MODELO DE DADOS DA INTERFACE

- Não existem perfis de cookie ou seletores de conta.
- Cada usuário tem no máximo um conjunto de cookies por ferramenta.
- A chave lógica é `user_id + service_id`.
- Remova do código relacionado ao Cookie Session Core os conceitos `profile`,
  `profiles`, `profile_id`, `profileId`, conta padrão e seletor de conta.
- Não altere ocorrências de "perfil" pertencentes a funcionalidades externas,
  como o perfil pessoal do usuário.

CONTRATO DA API

Usuário autenticado:

GET  /v1/services
POST /v1/services/:serviceId/launch

O corpo de `launch` deve ser exatamente um objeto vazio:

{}

Administração:

GET    /v1/admin/services
POST   /v1/admin/services
PUT    /v1/admin/services/:serviceId
GET    /v1/admin/services/:serviceId/users/:userId/cookies
POST   /v1/admin/services/:serviceId/users/:userId/cookies/import
DELETE /v1/admin/services/:serviceId/users/:userId/cookies

O corpo da importação deve conter somente:

{
  "cookies": "conteúdo DevTools, JSON, Netscape ou Cookie header"
}

Não encaminhe nenhuma outra rota do Railway. Em especial, não permita rotas
com `/v1/admin/cf/`, `clearance`, `solver`, `captcha` ou equivalentes.

LISTAGEM DE FERRAMENTAS

- `GET /v1/services` retorna todas as ferramentas habilitadas para o usuário
  autenticado.
- Não esconda uma ferramenta apenas porque os cookies ainda não foram
  configurados.
- Para `status: "ready"`, mostre o botão "Abrir".
- Para `status: "not_configured"`, mostre "Acesso ainda não configurado" e
  desabilite o botão.
- Não crie atribuição de ferramenta por usuário.
- Não exiba no catálogo valores, nomes técnicos ou detalhes dos cookies.

ABERTURA DA FERRAMENTA

Abra uma aba vazia de forma síncrona, antes da chamada assíncrona, para evitar
bloqueio de popup:

const newTab = window.open("about:blank", "_blank");
if (newTab) newTab.opener = null;

try {
  const result = await launchService(serviceId);
  if (newTab) newTab.location.replace(result.launch_url);
  else window.location.assign(result.launch_url);
} catch (error) {
  newTab?.close();
  throw error;
}

- `launchService` recebe somente `serviceId`.
- Não envie `user_id`, papel administrativo ou identificador de perfil.
- A identidade vem exclusivamente do JWT validado.
- Use a `launch_url` exatamente como recebida; não a monte, reescreva ou
  encaminhe novamente pela Edge Function.
- Nunca registre ou persista `launch_url` ou o token presente nela.
- Não faça prefetch da `launch_url`.

TRATAMENTO DE ERROS

- Exiba mensagens simples para 401, 403, 404, 409, 429, 502 e 503.
- Para 401, informe que a sessão expirou e ofereça entrar novamente.
- Para 403 administrativo, mostre permissão insuficiente.
- Para 409, informe que a configuração da ferramenta está indisponível.
- Para 429, informe que houve muitas tentativas e permita tentar mais tarde.
- Para 502 com `provider: "cloudflare"`, use a mensagem:
  "Esta ferramenta exige uma verificação de segurança que não pode ser
  concluída por esta integração. Use o acesso oficial do serviço."
- Para 503, informe indisponibilidade temporária.
- Não crie retry infinito. No máximo ofereça um botão manual "Tentar novamente"
  para falhas temporárias, nunca para Challenge Page incompatível.
- Não mostre Ray ID, headers internos, stack trace, cookies ou tokens ao usuário.

ADMINISTRAÇÃO

Na área administrativa existente:

1. mantenha cadastro e edição de ferramentas;
2. ao salvar `enabled=true`, a ferramenta deve aparecer para os usuários;
3. permita selecionar um usuário existente e uma ferramenta;
4. mostre somente quantidade de cookies, nomes, domínios, validade e status;
5. permita "Importar/substituir cookies";
6. permita "Remover cookies";
7. nunca mostre valor, prefixo, sufixo, cópia, download ou exportação de cookie;
8. nunca ofereça importação para usuários comuns;
9. não crie lista ou seletor de perfis;
10. exponha `proxy_hostname` como campo opcional "Subdomínio transparente",
    aceitando somente hostname sem `https://`, porta ou caminho;
11. inclua um aviso ao lado de `proxy_hostname`: "Um subdomínio dedicado não
    torna compatíveis serviços protegidos por Challenge Page.";
12. não adicione configurações de solver, CAPTCHA ou clearance.

EDGE FUNCTION `cookie-core`

Use o arquivo `lovable-integration/supabase/functions/cookie-core/index.ts` como
base, adaptando somente a verificação administrativa ao mecanismo real do
projeto.

- Valide o JWT com `supabase.auth.getUser(token)`.
- Restrinja CORS exatamente a `LOVABLE_APP_ORIGIN`.
- Rejeite origens ausentes ou diferentes.
- Use uma allowlist de rota + método com somente as rotas documentadas acima.
- Adicione `X-Cookie-Core-Admin` somente depois de validar a permissão
  administrativa server-side.
- Use `app_metadata.role` somente se essa for a regra real do projeto.
- Se o projeto usa tabela de papéis/permissões, reutilize a consulta server-side
  já existente.
- Nunca confie em `user_metadata`, `user_id`, `role` ou `is_admin` recebidos do
  navegador.
- Não siga redirects do Railway na Edge Function.
- Não encaminhe `Set-Cookie`, `Location` de lançamento, headers hop-by-hop ou
  headers internos que não estejam explicitamente previstos.
- Não registre Authorization, cookies, corpo de importação, `launch_url`, token
  de lançamento ou secrets.
- Preserve `Cache-Control: no-store` e `X-Request-ID` quando fornecido.

SECRETS EXCLUSIVAMENTE SERVER-SIDE

COOKIE_CORE_API_URL=https://SEU-SERVICO-RAILWAY
COOKIE_CORE_ADMIN_SECRET=<mesmo ADMIN_PROXY_SECRET do Railway>
LOVABLE_APP_ORIGIN=<origem HTTPS exata do frontend>
COOKIE_CORE_ADMIN_ROLE=admin

- Nunca use prefixo `VITE_` nesses secrets.
- Nunca coloque secrets em componentes React, arquivos públicos, localStorage,
  sessionStorage ou respostas da Edge Function.
- Reutilize o cliente Supabase existente no frontend.

VALIDAÇÃO OBRIGATÓRIA

Crie ou atualize testes que comprovem:

1. usuário autenticado lista as ferramentas habilitadas;
2. ferramenta sem cookies permanece visível como `not_configured`;
3. ferramenta configurada aparece como `ready`;
4. o launch envia somente `{}` e usa a `launch_url` recebida;
5. o frontend não envia `user_id`, perfil ou cookies;
6. usuário comum recebe 403 nas operações administrativas;
7. importar novamente substitui o conjunto anterior;
8. remover cookies muda o status para `not_configured`;
9. a Edge Function rejeita rota ou método fora da allowlist;
10. rotas contendo `cf`, `clearance`, `solver` ou `captcha` são rejeitadas;
11. nenhum secret aparece no bundle do frontend;
12. erros não exibem cookie, token, Ray ID ou stack trace;
13. não existe retry automático de Challenge Page;
14. a Edge Function `cookie-core` foi efetivamente publicada.

Ao terminar, informe:

- arquivos alterados;
- testes executados e resultados;
- URL/nome da Edge Function publicada;
- secrets que ainda precisam ser cadastrados manualmente, somente pelos nomes;
- qualquer ação manual restante.

Não declare a integração concluída se a Edge Function não tiver sido
publicada ou se os testes obrigatórios não tiverem sido executados.
```
