# Prompt único para o Lovable — cookies e localStorage no Cookie Session Core

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

- Não existem perfis de sessão ou seletores de conta.
- Cada usuário tem no máximo um conjunto de cookies e um conjunto de itens de
  `localStorage` por ferramenta.
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
GET    /v1/admin/services/:serviceId/users/:userId/localstorage
POST   /v1/admin/services/:serviceId/users/:userId/localstorage/import
DELETE /v1/admin/services/:serviceId/users/:userId/localstorage

O corpo da importação deve conter somente:

{
  "cookies": "conteúdo DevTools, JSON, Netscape ou Cookie header"
}

O corpo da importação de `localStorage` deve conter somente:

{
  "items": "{\"chave\":\"valor\",\"outra-chave\":\"outro valor\"}"
}

`items` é uma string contendo um objeto JSON simples de pares chave/valor; não
é o objeto JSON enviado diretamente. No formulário, aceite a colagem de um
objeto como `{"chave":"valor"}` e envie o texto integral no campo `items`.
Valores que sejam objetos, arrays, números, booleanos ou `null` podem permanecer
no JSON colado; o backend fará a serialização adequada. Não transforme o
conteúdo no frontend e não envie campos extras.

Não encaminhe nenhuma outra rota do Railway. Em especial, não permita rotas
com `/v1/admin/cf/`, `clearance`, `solver`, `captcha` ou equivalentes.

LISTAGEM DE FERRAMENTAS

- `GET /v1/services` retorna todas as ferramentas habilitadas para o usuário
  autenticado.
- Não esconda uma ferramenta apenas porque a sessão ainda não foi configurada.
- Para `status: "ready"`, mostre o botão "Abrir".
- Para `status: "not_configured"`, mostre "Acesso ainda não configurado" e
  desabilite o botão.
- Considere o `status` retornado por `GET /v1/services` como a fonte de verdade.
  A ferramenta pode estar `ready` somente com cookies, somente com
  `localStorage` ou com ambos; não recalcule esse status no frontend.
- Não crie atribuição de ferramenta por usuário.
- Não exiba no catálogo valores, nomes técnicos ou detalhes dos cookies ou do
  `localStorage`.

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
4. na mesma tela ou modal, crie duas seções lado a lado quando houver espaço
   e empilhadas em telas pequenas: "Cookies" e "localStorage";
5. na seção "Cookies", mostre somente quantidade, nomes, domínios, validade e
   status; inclua um campo de texto multilinha para colar os cookies e as ações
   "Importar/substituir cookies" e "Remover cookies";
6. na seção "localStorage", inclua um campo de texto multilinha ao lado do
   campo de cookies para colar um objeto JSON, com rótulo "localStorage (JSON)"
   e placeholder `{"chave":"valor"}`; inclua as ações
   "Importar/substituir localStorage" e "Remover localStorage";
7. consulte cookies e `localStorage` separadamente. Para `localStorage`, mostre
   somente `item_count`, status e a lista de chaves com `created_at` e
   `updated_at`; nunca mostre os valores;
8. mantenha estado, carregamento, erro, confirmação e resultado independentes
   para cada seção. Uma operação de cookies não pode limpar, reenviar ou
   sobrescrever o campo de `localStorage`, e vice-versa;
9. cada nova importação substitui integralmente apenas o conjunto do seu tipo:
   cookies substituem cookies; `localStorage` substitui `localStorage`;
10. antes de importar `localStorage`, valide apenas que o texto é JSON válido,
    que a raiz é um objeto simples, não array, e que possui ao menos uma chave.
    Chaves vazias e com espaços são válidas no Web Storage e devem ser
    preservadas exatamente como foram coladas.
    Preserve o texto e deixe as demais validações para o backend;
11. após importar ou remover um tipo, invalide/refaça as consultas de cookies,
    `localStorage` e da lista de serviços. Remover um tipo não torna
    necessariamente a ferramenta `not_configured`, pois o outro tipo pode
    continuar configurado;
12. trate `404` ao remover cookies ou `localStorage` como "já não configurado",
    atualize os dados e não restaure estado antigo da interface;
13. nunca mostre, copie, baixe, exporte, registre ou devolva valores, prefixos ou
    sufixos de cookies ou de `localStorage` depois da importação. Limpe o campo
    correspondente da memória da interface após sucesso;
14. nunca ofereça importação para usuários comuns;
15. não crie lista ou seletor de perfis;
16. exponha `proxy_hostname` como campo opcional "Subdomínio transparente",
    aceitando somente hostname sem `https://`, porta ou caminho;
17. inclua um aviso ao lado de `proxy_hostname`: "Um subdomínio dedicado não
    torna compatíveis serviços protegidos por Challenge Page.";
18. não adicione configurações de solver, CAPTCHA ou clearance.

Use confirmação específica nas remoções. "Remover cookies" deve apagar
somente cookies, e "Remover localStorage" deve apagar somente `localStorage`.
Nunca combine as duas exclusões em uma única chamada ou em uma ação ambígua.

EDGE FUNCTION `cookie-core`

Use o arquivo `lovable-integration/supabase/functions/cookie-core/index.ts` como
base, adaptando somente a verificação administrativa ao mecanismo real do
projeto.

- Valide o JWT com `supabase.auth.getUser(token)`.
- Restrinja CORS exatamente a `LOVABLE_APP_ORIGIN`.
- Rejeite origens ausentes ou diferentes.
- Use uma allowlist de rota + método com somente as rotas documentadas acima.
- Inclua explicitamente na allowlist os três endpoints de `localstorage`, com
  `POST` apenas em `/localstorage/import` e `GET`/`DELETE` apenas em
  `/localstorage`. Use exatamente `localstorage` em minúsculas na URL.
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
2. ferramenta sem cookies nem `localStorage` permanece visível como
   `not_configured`;
3. ferramenta somente com cookies, somente com `localStorage` ou com ambos
   aparece como `ready`;
4. o launch envia somente `{}` e usa a `launch_url` recebida;
5. o frontend não envia `user_id`, perfil, cookies ou itens de `localStorage` no
   launch;
6. usuário comum recebe 403 nas operações administrativas;
7. a importação de `localStorage` envia exatamente `{ items: textoColado }`;
8. importar novamente substitui somente o conjunto do mesmo tipo;
9. remover cookies preserva `localStorage`, e remover `localStorage` preserva
   cookies;
10. remover o único tipo configurado muda o status geral para `not_configured`;
11. a listagem administrativa de `localStorage` nunca recebe nem renderiza
   valores, apenas contagem, chaves e datas;
12. os campos de cookies e `localStorage` têm estados independentes e são limpos
   individualmente após uma importação bem-sucedida;
13. a Edge Function aceita os métodos corretos das rotas de cookies e
    `localstorage` e rejeita rota ou método fora da allowlist;
14. rotas contendo `cf`, `clearance`, `solver` ou `captcha` são rejeitadas;
15. nenhum secret aparece no bundle do frontend;
16. erros não exibem cookie, valor de `localStorage`, token, Ray ID ou stack
    trace;
17. não existe retry automático de Challenge Page;
18. a Edge Function `cookie-core` foi efetivamente publicada.

Ao terminar, informe:

- arquivos alterados;
- testes executados e resultados;
- URL/nome da Edge Function publicada;
- secrets que ainda precisam ser cadastrados manualmente, somente pelos nomes;
- qualquer ação manual restante.

Não declare a integração concluída se a Edge Function não tiver sido
publicada ou se os testes obrigatórios não tiverem sido executados.
```
