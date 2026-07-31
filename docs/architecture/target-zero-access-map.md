# Topologia alvo zero-access

Data: 2026-07-31

## Princípios

- O caminho principal nunca grava corpo ou anexo em claro.
- SMTP público continua interoperável com a internet.
- IMAP público não é parte do produto principal.
- SOGo não é cliente seguro principal.
- Rspamd pode ver inbound externo antes da criptografia, mas não conteúdo já E2EE.
- O navegador do usuário desbloqueia chaves privadas localmente.
- Nenhum segredo operacional do servidor descriptografa mailbox de usuário.

## Fluxo SMTP inbound alvo

1. Internet entrega para `postfix-mailcow`.
2. `postfix-mailcow` executa validações SMTP, TLS e mapas de domínio.
3. `rspamd-mailcow` analisa a mensagem antes da criptografia quando a mensagem chega em claro.
4. `postfix-mailcow` entrega destinatários locais para `zero-delivery`.
5. `zero-delivery` resolve mailbox, alias, catch-all e política de domínio.
6. `zero-delivery` busca chave pública ativa de cada destinatário no `zero-api` ou no banco.
7. `zero-delivery` cria envelope criptográfico por destinatário.
8. `zero-delivery` grava ciphertext em `zero-blob-vol-1`.
9. `zero-delivery` grava metadados mínimos no MariaDB.
10. `zero-worker` emite eventos e notificações.

## Fluxo de leitura alvo

1. Usuário acessa `zero-web` via `nginx-mailcow`.
2. `zero-web` autentica no `zero-api`.
3. Browser baixa chave privada criptografada e parâmetros KDF.
4. Browser deriva segredo local e desbloqueia a chave privada sem enviar a chave ao servidor.
5. Browser lista metadados via `zero-api`.
6. Browser baixa ciphertext e descriptografa localmente.

## Fluxo SMTP outbound alvo

1. Usuário compõe no `zero-web`.
2. Browser decide modo de envio por destinatário: local E2EE, OpenPGP externo, senha externa ou TLS-only.
3. Browser criptografa e assina quando houver chave.
4. `zero-api` recebe ciphertext e metadados mínimos.
5. `zero-worker` envia externo por `postfix-mailcow` quando necessário.
6. Cópia enviada fica criptografada em `zero-blob-vol-1`.

## Serviços novos

| Serviço | Função |
| --- | --- |
| `zero-api` | API Bun/TypeScript para auth, chaves, mailbox, WKD, metadados e blobs. |
| `zero-web` | Cliente web seguro, buildado com Bun e servido por nginx ou container estático. |
| `zero-delivery` | Transporte interno de entrega local, responsável por criptografar antes de persistir. |
| `zero-worker` | Filas, envio externo, expiração, notificações e tarefas de key transparency. |
| `zero-blob-vol-1` | Volume de armazenamento de ciphertext. Pode virar serviço dedicado depois. |

## Serviços removidos do caminho principal

| Serviço | Tratamento |
| --- | --- |
| `dovecot-mailcow` | Deixa de ser backend de mailbox principal. IMAP futuro deve ser via bridge local. |
| `sogo-mailcow` | Sai do produto principal. Groupware criptografado deve ser projeto separado. |
| `memcached-mailcow` | Só permanece se algum componente mantido ainda exigir. |
| `ofelia-mailcow` | Pode permanecer, mas sem dependência de SOGo/Dovecot. |

## Contratos não negociáveis

- `ZERO_ACCESS_REQUIRED` deve ser `y` em ambientes normais.
- `zero-delivery` deve falhar entrega local se o destinatário não tiver chave ativa.
- `zero-api` não aceita chave privada em claro.
- `zero-api` não expõe corpo descriptografado.
- `zero-worker` não envia DSN com corpo original em claro.
- Quarentena de conteúdo claro só pode ocorrer antes da criptografia e com política explícita.
- Qualquer fallback TLS-only deve aparecer claramente no `zero-web`.

## Ordem de adaptação dos componentes mailcow

1. Propagar `ZERO_ACCESS_REQUIRED`.
2. Fazer `watchdog-mailcow` parar de assumir Dovecot/SOGo como obrigatórios quando zero-access estiver ativo. Concluído no Compose.
3. Fazer `nginx-mailcow` servir rotas novas para `zero-web`, `zero-api` e WKD.
4. Adicionar `zero-api` com healthcheck. Concluído como serviço `zero-api-mailcow`.
5. Adicionar schema `zero_*` e registro seguro de chaves. Schema concluído; registro em memória iniciado no `zero-api`.
6. Adicionar `zero-delivery`. Iniciado como serviço interno com validação de ciphertext e resolução de chave do destinatário via `zero-api`.
7. Alterar Postfix para rotear mailbox local para `zero-delivery`.
8. Remover portas públicas IMAP/POP3/Sieve do caminho padrão.
9. Remover SOGo da dependência do nginx/ofelia.
10. Migrar UI/admin necessário para políticas zero-access.
