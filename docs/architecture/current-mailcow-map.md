# Mapa atual do mailcow neste fork

Data: 2026-07-31

## Fluxo SMTP inbound atual

1. A internet entrega SMTP público para `postfix-mailcow` nas portas `25`, `465` e `587`.
2. `postfix-mailcow` aplica mapas SQL, restrições, TLS, milter e roteamento.
3. `rspamd-mailcow` recebe a mensagem via milter em `9900`, analisa spam, vírus, símbolos, quarentena e metadados.
4. Postfix entrega mailbox local via `virtual_transport = lmtp:inet:dovecot:24`.
5. `dovecot-mailcow` grava em Maildir em `vmail-vol-1`.
6. Dovecot usa `mail_crypt_global_private_key` e `mail_crypt_global_public_key` em `crypt-vol-1`.

Resultado: há criptografia operacional em repouso, mas a chave global fica no servidor. Isso não é zero-access.

## Fluxo de leitura atual

1. Cliente IMAP/POP3/Sieve conecta diretamente em `dovecot-mailcow`.
2. SOGo conecta aos serviços de e-mail e groupware com acesso server-side.
3. `nginx-mailcow` serve UI/admin/SOGo/Rspamd e encaminha autenticação interna.
4. `php-fpm-mailcow` executa admin, auth, API, templates, cron jobs e integração SOGo.

Resultado: Dovecot e SOGo esperam conteúdo legível para o usuário depois da autenticação. Isso conflita com zero-access server-side.

## Fluxo SMTP outbound atual

1. Usuário autentica por SMTP submission em `postfix-mailcow`.
2. Postfix valida sender ACL, políticas TLS e mapas SQL.
3. Rspamd assina DKIM e aplica política quando configurado.
4. Postfix entrega para MX externo.

Resultado: o servidor processa MIME em claro para e-mails enviados por SMTP tradicional.

## Componentes classificados

| Componente | Decisão | Motivo |
| --- | --- | --- |
| `postfix-mailcow` | Manter e adaptar | Continua sendo o melhor ponto de interoperabilidade SMTP público. Deve rotear mailbox local para `zero-delivery`. |
| `rspamd-mailcow` | Manter e adaptar | Deve analisar inbound externo antes da criptografia. Não deve depender de conteúdo em claro após persistência. |
| `dovecot-mailcow` | Substituir no caminho principal | IMAP público e Maildir legível não combinam com zero-access. Pode ficar temporariamente enquanto o fluxo novo nasce. |
| `sogo-mailcow` | Remover do caminho principal | Webmail/groupware server-side espera conteúdo legível. Calendário/contatos devem ser reavaliados depois. |
| `php-fpm-mailcow` | Reduzir e adaptar | Admin atual pode servir como ponto de partida para domínios/mailboxes, mas a API segura deve ir para `zero-api`. |
| `nginx-mailcow` | Manter e adaptar | Deve servir `zero-web`, `zero-api`, WKD e portal público seguro. |
| `mysql-mailcow` | Manter e adaptar | Pode armazenar metadados e chaves criptografadas. Não deve armazenar corpo claro. |
| `redis-mailcow` | Manter | Sessões, filas leves, rate limit e eventos transitórios. |
| `acme-mailcow` | Manter | Certificados continuam necessários para SMTP, HTTPS e WKD. |
| `unbound-mailcow` | Manter | DNS local continua útil para SMTP, DKIM, SPF, DMARC, DANE e WKD externo. |
| `clamd-mailcow` | Avaliar | Útil para inbound externo antes da criptografia; inútil para E2EE já criptografado. |
| `olefy-mailcow` | Avaliar | Mesma lógica do ClamAV. |
| `watchdog-mailcow` | Adaptar | Deve parar de tratar Dovecot/SOGo como essenciais quando o caminho zero-access estiver pronto. |
| `dockerapi-mailcow` | Avaliar | Útil para operações Docker internas, mas aumenta superfície privilegiada. |
| `ofelia-mailcow` | Adaptar | Pode agendar tarefas, mas deve perder dependência de SOGo/Dovecot. |

## Pontos de risco imediatos

- `crypt-vol-1` guarda chave global útil para descriptografar dados atuais.
- `vmail-vol-1` e `vmail-index-vol-1` pertencem ao modelo Dovecot.
- `sogo-userdata-backup-vol-1` pode carregar dados de groupware server-side.
- `quarantine.msg` no banco pode armazenar conteúdo em claro.
- Logs e templates podem conter assuntos, remetentes e trechos de mensagem.
- IMAP/POP3/Sieve públicos reforçam o modelo antigo e devem sair do produto principal.

## Primeira adaptação realizada

- `ZERO_ACCESS_REQUIRED=y` passa a existir no `generate_config.sh`.
- `ZERO_ACCESS_REQUIRED` é propagado para serviços do caminho de e-mail/web no `docker-compose.yml`.
- `generate_config.sh` passa a gerar IMAP, IMAPS, POP3, POP3S e Sieve bindados em `127.0.0.1`.
- Os fallbacks do `docker-compose.yml` para IMAP, IMAPS, POP3, POP3S e Sieve também passam a bindar em `127.0.0.1`.
- `SKIP_SOGO=y` passa a ser o default gerado.
- `zero-api-mailcow` passa a existir como serviço Bun interno com healthcheck em `/health`.
- `zero-blob-vol-1` passa a existir como volume dedicado para ciphertext do `zero-api`.
- `zero-delivery-mailcow` passa a existir como serviço Bun interno com healthcheck e validação inicial de entregas criptografadas.
- `zero-api` passa a registrar chaves de usuário apenas com `encryptedPrivateKey` e expor consulta pública local sem material privado.
- `zero-delivery` passa a resolver chave ativa do destinatário via `zero-api` antes de aceitar entrega.
- A suíte Bun cobre defaults zero-access, validade do Compose, bind local de protocolos legados e comportamento inicial do `zero-api`.
- `nginx-mailcow`, `ofelia-mailcow` e `watchdog-mailcow` deixam de ter dependências duras de SOGo/Dovecot no caminho zero-access.
- Essa flag ainda não muda comportamento sozinha; ela cria o contrato para as próximas alterações recusarem fluxos não zero-access.
