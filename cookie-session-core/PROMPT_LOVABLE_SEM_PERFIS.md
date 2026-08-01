# Prompt Lovable — ferramentas globais sem perfis

Anexe ou disponibilize ao Lovable estes arquivos:

- `lovable-integration/cookieCoreClient.ts`
- `lovable-integration/supabase/functions/cookie-core/index.ts`

Depois envie o texto abaixo no chat do projeto Lovable:

```text
Atualize o projeto Lovable EXISTENTE para integrar o Cookie Session Core
implantado no Railway. Faça alterações reais e publique a Edge Function.

Antes de editar, inspecione a autenticação, a regra administrativa, os
componentes, as rotas e o padrão visual existentes. Preserve o layout atual.

ARQUITETURA OBRIGATÓRIA

- Lovable continua responsável por login, usuários, administração e interface.
- A Edge Function cookie-core valida o JWT e encaminha chamadas ao Railway.
- O Railway atua como reverse proxy e cofre de cookies.
- Não crie outro login, outro projeto, outro cliente Supabase ou outra tabela de usuários.
- Não implemente Playwright, iframe, canvas ou navegador remoto.
- O navegador nunca pode receber cookies do serviço original.
- Nenhum secret pode usar prefixo VITE_ ou aparecer no bundle frontend.

REGRA NOVA: NÃO EXISTEM PERFIS

- Remova da interface e do código os conceitos de perfil, conta, profile_id,
  profileId, label de conta, conta padrão e seletor de conta.
- Cada usuário possui no máximo um conjunto de cookies por ferramenta.
- A chave lógica é somente user_id + service_id.
- Importar novamente substitui integralmente os cookies anteriores daquele
  usuário e ferramenta.
- Não crie compatibilidade visual com perfis antigos.

FERRAMENTAS VISÍVEIS PARA TODOS

- GET /v1/services retorna todas as ferramentas habilitadas para todo usuário autenticado.
- Não esconda uma ferramenta porque o usuário ainda não possui cookies.
- Cada ferramenta possui status:
  - ready: mostrar botão "Abrir";
  - not_configured: mostrar "Acesso ainda não configurado" e desabilitar o botão.
- Ao publicar/ativar uma ferramenta no painel administrativo, ela deve aparecer
  automaticamente para todos os usuários autenticados.
- Não crie tabela ou tela para atribuir ferramenta a usuário.

ROTAS PERMITIDAS

Usuário autenticado:

GET  /v1/services
POST /v1/services/:serviceId/launch

O POST de launch deve enviar somente um objeto vazio:

{}

Administração:

GET    /v1/admin/services
POST   /v1/admin/services
PUT    /v1/admin/services/:serviceId
GET    /v1/admin/services/:serviceId/users/:userId/cookies
POST   /v1/admin/services/:serviceId/users/:userId/cookies/import
DELETE /v1/admin/services/:serviceId/users/:userId/cookies

Importação:

{
  "cookies": "conteúdo DevTools, JSON, Netscape ou Cookie header"
}

Nunca envie label, profile_id, profileId ou is_default.

ADMINISTRAÇÃO

Na administração existente:

1. mantenha cadastro e edição de ferramentas;
2. ao salvar uma ferramenta enabled=true, considere-a publicada para todos;
3. permita selecionar um usuário existente e uma ferramenta;
4. mostre apenas metadados: quantidade, nomes, domínios, validade e status;
5. permita "Importar/substituir cookies";
6. permita "Remover cookies";
7. nunca mostre valor, prefixo, sufixo, cópia ou exportação de cookie;
8. não mostre lista, formulário ou seletor de perfis.

ABERTURA DA FERRAMENTA

Crie a aba de forma síncrona antes da chamada assíncrona:

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

- launchService recebe somente serviceId.
- Não envie user_id; a identidade vem do JWT.
- Não envie profileId.
- launch_url deve abrir diretamente em https://servico.jbtools.site/proxy/...
- Não encaminhe launch_url novamente pela Edge Function.

EDGE FUNCTION

Use o index.ts fornecido como fonte da função cookie-core.

- Valide o JWT do usuário.
- Restrinja CORS exatamente a LOVABLE_APP_ORIGIN.
- Permita somente as rotas listadas.
- Adicione X-Cookie-Core-Admin somente após validar administrador.
- Use app_metadata.role somente se essa já for a regra real do projeto.
- Se o projeto usa tabela própria de papéis/permissões, adapte a verificação ao
  mecanismo server-side existente.
- Nunca confie em user_metadata, user_id, role ou is_admin enviados pelo navegador.
- Nunca registre Authorization, cookies, launch_url, launch token ou corpo de importação.

SECRETS SERVER-SIDE ESPERADOS

COOKIE_CORE_API_URL=https://servico.jbtools.site
COOKIE_CORE_ADMIN_SECRET=<mesmo ADMIN_PROXY_SECRET do Railway>
LOVABLE_APP_ORIGIN=<origem exata deste frontend>
COOKIE_CORE_ADMIN_ROLE=admin

Use o cliente de autenticação já existente ao integrar cookieCoreClient.ts.

LIMPEZA OBRIGATÓRIA

Pesquise o projeto inteiro e remova referências a:

- profiles
- profile
- profile_id
- profileId
- account profile
- conta padrão
- seletor de conta

Não altere ocorrências que pertençam a funcionalidades externas não relacionadas
ao Cookie Session Core.

VALIDAÇÃO FINAL

1. Usuário autenticado lista todas as ferramentas habilitadas.
2. Ferramenta sem cookies aparece como not_configured.
3. Ferramenta com cookies do usuário aparece como ready.
4. Usuário A nunca utiliza cookies do usuário B.
5. Usuário comum recebe 403 nas rotas administrativas.
6. Importar novamente substitui o conjunto anterior.
7. Remover cookies muda a ferramenta para not_configured sem ocultá-la.
8. O botão Abrir não envia profileId.
9. Nenhum secret aparece no bundle.
10. A Edge Function cookie-core foi efetivamente publicada.

Ao terminar, informe os arquivos alterados, a URL da função publicada e qualquer
ação manual ainda necessária.
```
