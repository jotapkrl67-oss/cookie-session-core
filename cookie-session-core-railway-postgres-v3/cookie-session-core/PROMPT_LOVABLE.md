# Prompt aprimorado para o Lovable

Cole todo o conteúdo abaixo no Lovable. Antes disso, envie a pasta
`cookie-session-core` para o mesmo repositório do seu projeto.

```text
Atue como engenheiro sênior responsável por integrar uma funcionalidade sensível
em um sistema Lovable já existente. Faça alterações reais no projeto; não entregue
somente exemplos, pseudocódigo ou uma explicação.

## Objetivo

Integrar ao meu sistema existente o módulo backend "Cookie Session Core", disponível
na pasta /cookie-session-core.

Esse módulo permite que:

1. somente o administrador cadastre serviços HTTPS;
2. somente o administrador importe cookies de contas;
3. cada conjunto de cookies pertença a exatamente um usuário, serviço e perfil;
4. o usuário comum apenas veja as contas autorizadas e clique em "Abrir";
5. o backend abra o serviço em um BrowserContext Playwright isolado;
6. valores de cookies nunca sejam exibidos ou compartilhados.

O recurso deve ser genérico e funcionar com diferentes sites autenticados por
cookies, respeitando as políticas configuradas para cada serviço.

## Regra principal

Este é um recurso novo dentro do sistema existente, não um novo sistema.

- NÃO recrie autenticação, cadastro, sidebar, dashboard ou tema.
- NÃO substitua o layout global.
- NÃO crie outra aplicação React.
- NÃO duplique tabelas de usuários ou permissões que já existam.
- NÃO use dados fictícios quando já houver dados reais no projeto.
- Preserve os componentes, rotas, padrões visuais, idioma e responsividade atuais.
- Adicione somente as telas, controles, serviços e rotas necessários.

## Primeiro passo obrigatório: inspeção

Antes de editar:

1. examine a estrutura atual do projeto;
2. identifique como Supabase Auth é inicializado;
3. descubra onde o papel/permissão de administrador é armazenado;
4. identifique os componentes já usados para formulário, modal, toast, tabela,
   loading, confirmação e tratamento de erro;
5. identifique como as migrations e Edge Functions são organizadas;
6. leia integralmente:
   - /cookie-session-core/README.md
   - /cookie-session-core/sql/schema.sql
   - /cookie-session-core/src/cookie_session_core/core.py
   - /cookie-session-core/src/cookie_session_core/playwright_adapter.py

Reutilize os padrões encontrados. Não invente uma segunda arquitetura.

## Limite técnico importante

O módulo Python e o Playwright NÃO podem rodar no navegador nem dentro de uma
Supabase Edge Function.

Arquitetura correta:

Frontend Lovable
  -> Supabase Auth
  -> Edge Function/rota segura do sistema
  -> backend externo Cookie Session Core
  -> PostgreSQL/Supabase
  -> worker Playwright isolado
  -> URL temporária da sessão remota

A Edge Function apenas:

- valida o JWT Supabase;
- obtém user.id e permissões da sessão/banco;
- valida entrada básica;
- encaminha a operação ao backend externo;
- devolve uma resposta sanitizada.

Ela não deve descriptografar cookies, executar Playwright ou receber chaves de
criptografia.

Use secrets server-side:

- COOKIE_CORE_API_URL
- COOKIE_CORE_ADMIN_SECRET, somente na Edge Function
- COOKIE_VAULT_KEY_BASE64, apenas no backend Python
- LAUNCH_TOKEN_PEPPER_BASE64, apenas no backend Python
- DATABASE_URL, apenas no backend Python/ambiente autorizado

Nenhum desses valores pode usar prefixo VITE_ ou aparecer no bundle do frontend.
O backend HTTP, o Dockerfile e o WebSocket já estão implementados na pasta.
Reutilize:

- /cookie-session-core/lovable-integration/cookieCoreClient.ts
- /cookie-session-core/lovable-integration/supabase/functions/cookie-core/index.ts

Copie e adapte esses arquivos aos padrões do projeto existente. NÃO reimplemente o
Playwright no Lovable e NÃO crie um mock que finja ter aberto uma sessão real.

## Autenticação e autorização

Continue usando exclusivamente o Supabase Auth existente.

- Nunca aceite user_id, role, is_admin ou permission como verdade vinda do body,
  query string, localStorage ou metadata editável pelo usuário.
- Obtenha o usuário pelo JWT validado no servidor.
- Resolva a permissão administrativa usando o mecanismo já existente no projeto.
- Caso o projeto ainda não tenha uma permissão administrativa segura, crie uma
  tabela/claim protegida e documente a decisão.
- Toda importação, edição, revogação ou listagem administrativa deve ser bloqueada
  no backend para usuários comuns, mesmo que tentem chamar a rota manualmente.
- O usuário comum só pode lançar perfis cujo user_id seja exatamente o seu.
- Um administrador pode atribuir cookies a outro usuário, mas essa ação deve ser
  auditada com actor_user_id e subject_user_id separados.

## Banco de dados

Converta /cookie-session-core/sql/schema.sql para uma migration Supabase seguindo
o padrão existente do repositório.

Requisitos:

- user_id deve receber auth.users.id convertido em texto;
- não exponha cookie_core_stored_cookies, cookie_core_launch_tokens ou cookie_core_audit_logs ao cliente;
- anon e authenticated não podem selecionar encrypted_value ou nonce;
- somente backend/Service Role pode gravar ou ler as tabelas sensíveis;
- todas as operações devem usar a chave composta:
  user_id + service_id + profile_id;
- nunca consulte perfil somente por profile_id;
- launch token deve ser armazenado apenas como hash;
- token deve expirar em 30 segundos;
- consumo deve ser atômico e de uso único;
- exclusão/revogação de perfil deve invalidar lançamentos pendentes;
- auditoria guarda nomes/quantidade/ação, nunca valores de cookies.

Não crie cookies reais em migrations, seed ou fixtures.

## Contrato das Edge Functions/rotas

Adapte os nomes ao padrão existente, mas mantenha estes comportamentos:

### 1. Listar serviços disponíveis

GET /v1/services

Resposta para usuário comum:

{
  "services": [
    {
      "id": "uuid",
      "name": "Nome",
      "category": "Categoria",
      "enabled": true,
      "profiles": [
        {
          "id": "uuid",
          "label": "Conta 1",
          "is_default": true,
          "status": "ready"
        }
      ]
    }
  ]
}

Retorne apenas serviços/perfis atribuídos ao usuário autenticado. Nunca retorne
metadados internos ou cookies.

### 2. Criar ou atualizar serviço — somente administrador

POST /v1/admin/services
PUT /v1/admin/services/:serviceId

Entrada:

{
  "name": "Claude",
  "category": "Assistentes",
  "upstream_url": "https://claude.ai/",
  "allowed_domains": ["claude.ai"],
  "allowed_paths": ["/"],
  "allowed_cookie_names": [],
  "enabled": true
}

Valide HTTPS, hostname, tamanho dos campos e listas. Quando opções avançadas forem
omitidas, derive allowed_domains do hostname e use ["/"] para allowed_paths.

### 3. Importar conta — somente administrador

POST /v1/admin/services/:serviceId/users/:userId/profiles/import

Entrada:

{
  "label": "Conta principal",
  "cookies": "conteúdo colado pelo administrador",
  "profile_id": null,
  "is_default": true
}

Aceite:

- tabela copiada do DevTools Chrome/Edge;
- JSON de extensão;
- arquivo Netscape;
- Cookie header.

Limites:

- no máximo 100 KB;
- no máximo 200 cookies;
- label com no máximo 80 caracteres;
- validar domínio, path e allowed_cookie_names;
- não registrar request body;
- não devolver valores.

Resposta:

{
  "id": "uuid",
  "label": "Conta principal",
  "cookie_count": 12,
  "is_default": true,
  "status": "ready"
}

### 4. Metadados e revogação — somente administrador

GET /v1/admin/services/:serviceId/users/:userId/profiles
DELETE /v1/admin/services/:serviceId/users/:userId/profiles/:profileId

A listagem pode mostrar:

- label;
- quantidade;
- domínios;
- nomes de cookies;
- validade;
- ativo, expirado ou revogado.

Não mostrar value, encrypted_value, nonce, pedaços do valor, botão copiar ou
exportação.

Antes de DELETE, exiba confirmação informando usuário, serviço e perfil.

### 5. Abrir serviço — usuário autenticado

POST /v1/services/:serviceId/launch

Entrada opcional:

{
  "profile_id": "uuid"
}

O backend deve ignorar qualquer user_id enviado e usar o usuário autenticado.
Verifique propriedade e permissão antes de chamar issue_launch().

Resposta:

{
  "launch_url": "URL HTTPS temporária",
  "expires_in": 30
}

O frontend deve navegar para launch_url. Não coloque cookies, profile_id ou user_id
sensível na URL. O token deve ser aleatório, opaco, temporário e de uso único.

## Fluxo interno obrigatório

1. O usuário autenticado solicita abertura.
2. O backend resolve user_id pela sessão validada.
3. O backend verifica serviço, acesso e profile_id.
4. issue_launch() gera token aleatório de 30 segundos.
5. Apenas o hash é gravado.
6. consume_launch() remove/consome o token atomicamente.
7. O backend descriptografa somente os cookies daquela tupla
   user_id + service_id + profile_id.
8. isolated_cookie_session() cria um BrowserContext novo.
9. Cookies são injetados antes de navegar para upstream_url.
10. A sessão remota é entregue por URL HTTPS/WebSocket protegida.
11. Ao fechar, cookies permitidos e rotacionados são sincronizados.
12. O BrowserContext é destruído.

Nunca reutilize BrowserContext, Page, cookie jar, storage state ou cache autenticado
entre usuários, mesmo quando usam o mesmo serviço ou a mesma conta nominal.

## Interface administrativa

Integre dentro da área administrativa já existente.

Crie uma seção discreta chamada "Contas de serviços" ou nome equivalente ao padrão
do projeto.

Fluxo simples:

1. escolher usuário;
2. escolher serviço;
3. colar cookies;
4. salvar conta.

Campos principais:

- usuário;
- serviço;
- textarea de cookies;
- botão salvar.

Campos opcionais dentro de "Opções avançadas":

- nome da conta;
- tornar padrão;
- políticas de cookie ao editar serviço.

Após colar, detecte localmente apenas o formato e a quantidade aproximada. Não
grave o texto em localStorage, sessionStorage, IndexedDB, analytics ou estado
global persistente. Limpe o textarea imediatamente após sucesso e também ao sair
da tela.

Mostre:

- sucesso com quantidade importada;
- erro sanitizado;
- contas já configuradas;
- status pronto/expirado/revogado;
- ação revogar.

Não mostre:

- valores de cookies;
- preview parcial;
- botão revelar;
- botão copiar/exportar;
- cookies no console ou ferramentas de telemetria.

## Interface do usuário

Reutilize os cards ou lista de serviços existentes.

- Mostre apenas serviços autorizados.
- Mostre o label do perfil, nunca dados do cookie.
- Se houver um perfil, "Abrir" lança diretamente.
- Se houver vários, permita escolher a conta em modal existente.
- Desabilite o botão durante a chamada para evitar lançamentos duplicados.
- Abra launch_url na mesma aba, salvo se o comportamento atual do produto usar
  nova aba.
- Mostre mensagens claras para perfil ausente, revogado, expirado, indisponibilidade
  do worker e token expirado.
- Não use iframe comum para o site terceiro. Muitos serviços bloqueiam framing.

## Segurança operacional

Implemente:

- HTTPS obrigatório;
- validação de origem;
- CSRF se a aplicação autentica com cookies;
- CORS restrito ao domínio real do sistema;
- rate limit por usuário:
  - importação: 10 por minuto;
  - lançamento: 20 por minuto;
  - troca de token: 30 por minuto;
- timeout de rede configurável;
- payload máximo de 100 KB antes do parser;
- Content-Security-Policy compatível com o projeto;
- no-store em respostas autenticadas;
- redaction de Authorization, Cookie, Set-Cookie, cookies e tokens nos logs;
- auditoria de criar serviço, importar, lançar, injetar, rotacionar e revogar;
- limpeza periódica de cookie_core_launch_tokens expirados;
- encerramento de sessões remotas no logout/revogação quando suportado.

Cookies de Cloudflare e proteções anti-bot podem ser vinculados ao IP e à impressão
digital do navegador original. Não tente burlar essas proteções. Mostre uma mensagem
administrativa indicando que o cookie precisa ser renovado quando necessário.
Prefira OAuth/OIDC oficial quando o serviço suportar.

## Estados e tratamento de erro

Implemente estados loading, vazio, sucesso e erro seguindo os componentes existentes.
Sanitize mensagens vindas do backend. Nunca mostre stack trace ou request body.

Mapeie pelo menos:

- 400: importação ou configuração inválida;
- 401: sessão principal expirada;
- 403: permissão negada;
- 404: serviço/perfil inexistente;
- 409: perfil duplicado ou token já consumido;
- 413: importação maior que o limite;
- 429: limite de requisições;
- 502/503: worker remoto indisponível.

## Testes obrigatórios

Crie testes automatizados usando somente cookies falsos:

1. administrador pode importar;
2. usuário comum não pode importar;
3. usuário A não lista perfil do usuário B;
4. usuário A não lança perfil do usuário B;
5. alterar user_id no body não muda o usuário autenticado;
6. cookie de domínio não permitido é rejeitado;
7. cookie acima do limite é rejeitado;
8. launch token funciona uma vez;
9. replay do token falha;
10. token expirado falha;
11. revogação invalida novas aberturas;
12. respostas e logs não contêm valores de cookies;
13. dois lançamentos simultâneos usam BrowserContexts diferentes;
14. falha ao abrir sempre fecha o contexto criado.

## Ordem de execução

Execute nesta ordem:

1. inspecionar o projeto e resumir a arquitetura encontrada;
2. aplicar migration;
3. copiar e adaptar o cliente/Edge Function fornecidos;
4. implementar autorização server-side;
5. criar hooks e tipos;
6. integrar UI administrativa;
7. integrar botão de abertura na UI existente;
8. adicionar tratamento de erros;
9. criar testes;
10. executar lint, typecheck, testes e build;
11. corrigir todos os erros encontrados;
12. documentar configuração e implantação.

Não pare após criar a aparência. A funcionalidade deve estar ligada às rotas reais.
Não declare que a sessão Playwright funciona se o backend externo não estiver
configurado e testado.

## Critérios de aceite

Considere concluído somente quando:

- o layout atual permanece reconhecível e funcional;
- administrador consegue cadastrar serviço e importar conta;
- usuário comum não encontra nenhuma forma de enviar cookies;
- valores sensíveis não aparecem em UI, resposta, banco acessível ao cliente ou log;
- usuário A não acessa cookies/perfis do usuário B;
- launch token expira e não aceita replay;
- o botão Abrir usa uma rota real;
- cada abertura cria contexto isolado;
- revogação impede nova abertura;
- lint, typecheck, testes e build passam;
- README informa secrets, URL do backend e procedimento de deploy.

## Formato da resposta final

Ao terminar, informe objetivamente:

1. arquivos criados e alterados;
2. migration aplicada;
3. rotas/Edge Functions implementadas;
4. componentes integrados;
5. testes executados e resultados;
6. secrets que preciso configurar;
7. qualquer dependência externa ainda necessária;
8. como validar manualmente sem usar cookies reais no repositório.

Não inclua valores de cookies, tokens ou secrets na resposta.
```
