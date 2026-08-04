# Runbook do Cloudflare Cookie Provider

Todos os diagnósticos devem usar somente IDs, origem sanitizada, categoria e
métricas. Nunca copie tokens, `Cookie`, `Set-Cookie`, grants, HTML ou senha de
proxy para tickets ou logs.

| Incidente | Detectar | Causa provável | Ação imediata | Correção definitiva / risco de repetir |
| --- | --- | --- | --- | --- |
| Provider 401 | erro `CloudflareProviderAuthenticationError`, circuito aberto | token divergente/rotacionado | compare configuração sem imprimir valores; use token next durante rotação | alinhar secrets e remover token antigo; retry agressivo só prolonga o incidente |
| Timeout | categoria timeout e duração no limite | destino lento, DNS, proxy ou browser | verificar `/health/ready`, egress e timeout | corrigir rede/política; aumentar timeout eleva ocupação da fila |
| Fila saturada | `/solve` 429, contadores active/queued | concorrência acima da memória | reduzir tráfego/aguardar `Retry-After` | dimensionar instância ou concorrência após teste de carga; aumentar concurrency pode causar OOM |
| Browser crash recorrente | 502 `Browser operation failed` | memória, versão/browser ou proxy | reiniciar uma instância e reduzir concorrência | fixar versão compatível e memória; retries podem criar crash loop |
| Proxy indisponível | falha de browser após configurar proxy | DNS, credencial ou firewall | testar conectividade do Railway sem expor credenciais | monitorar proxy e redundância autorizada; não remover SSRF/TLS para contornar |
| Clearance emitido, core recebe 403 | solve success seguido de challenge | IP/fingerprint/Client Hints divergentes | invalidar uma vez e conferir mesmo egress | manter request no browser quando necessário; repetir solve pode gerar tempestade |
| Aumento de solves | `cf_provider_calls`, owners/waiters | clearance curto, mudança WAF ou falso positivo | conferir classificação e TTL | ajustar política/origem; não tratar 429 como challenge |
| Store crescendo | `cached_sessions` perto do limite | muitas origens/egress | invalidar chaves inativas via DELETE admin | reduzir allowlist/TTL; limpeza global derruba sessões válidas |
| Circuito aberto | status admin `circuit_state=open` | três falhas transitórias ou autenticação | corrigir provider e aguardar janela de 30 s | alertar por categoria; forçar retries sobrecarrega dependência |
| Suspeita de segredo vazado | acesso anômalo/401, ocorrência em log | token ou proxy credential exposto | revogar e rotacionar imediatamente; preservar evidência redigida | secret scanning e acesso mínimo; repetir token comprometido mantém acesso |
| Rotação do token | mudança planejada | manutenção | configurar `TOKEN_NEXT`, trocar core, promover next | remover antigo após validação; trocar ambos simultaneamente pode causar indisponibilidade |
| Rollback emergencial | regressão após deploy | versão/configuração | `CF_AUTO_REFRESH=false`; redeploy da imagem anterior do serviço | investigar offline; rollback perde apenas sessões transitórias, não cookies do cofre |

Health checks não abrem Chromium: `/health/live` confirma processo e
`/health/ready` confirma inicialização essencial. Após qualquer ação, valide os
dois endpoints, `/v1/admin/cf/status`, uma origem autorizada e a ausência de
segredos nos logs.
