# Plano para transformar este fork do mailcow em e-mail zero-access

Data: 2026-07-31

## Objetivo

Transformar este fork do mailcow em uma plataforma auto-hospedada de e-mail com privacidade próxima a Proton Mail e Tuta Mail:

- O servidor não deve conseguir ler corpo e anexos das mensagens armazenadas.
- Mensagens entre usuários locais devem ser criptografadas de ponta a ponta automaticamente.
- Mensagens externas devem continuar interoperáveis com SMTP, com proteção máxima possível por TLS, OpenPGP, WKD, Autocrypt ou mensagens protegidas por senha.
- SMTP público deve continuar interoperável com a internet. IMAP/SOGo não são requisito do produto zero-access principal.
- Não haverá retrocompatibilidade com instalações existentes de mailcow nem promessa de upgrade in-place. Este fork deve evoluir como uma aplicação nova, usando componentes do mailcow apenas enquanto forem úteis.

## Definições essenciais

Zero-access não é a mesma coisa que E2EE.

Zero-access em repouso significa que mensagens recebidas de qualquer lugar são armazenadas criptografadas com chave pública do usuário, e o servidor não possui a chave privada útil para descriptografar. Isso protege contra operador, backup vazado, volume Docker copiado e invasão posterior do servidor.

E2EE significa que a mensagem sai do cliente do remetente já criptografada para o destinatário. Isso protege também o trânsito interno e impede que o servidor veja conteúdo antes de salvar.

SMTP externo comum não oferece E2EE por padrão. Para destinatários fora da instância, a plataforma deve usar OpenPGP quando houver chave pública confiável, ou mensagem protegida por senha quando não houver.

## Estado atual do fork

Este repositório ainda é majoritariamente mailcow tradicional:

- `docker-compose.yml` orquestra MariaDB, Redis, Postfix, Dovecot, Rspamd, SOGo, nginx/php-fpm, ACME, clamd e serviços auxiliares.
- `data/conf/postfix/main.cf` entrega mensagens virtuais via `virtual_transport = lmtp:inet:dovecot:24`.
- `data/conf/dovecot/dovecot.conf` usa Maildir em `/var/vmail/%d/%n`, expõe IMAP/POP3/Sieve/LMTP e já tem `mail_attachment_fs = crypt`.
- O mesmo arquivo configura `mail_crypt_global_private_key` e `mail_crypt_global_public_key` em `/mail_crypt`, montado pelo volume `crypt-vol-1`.
- Essa configuração atual cifra dados em repouso, mas com chave global do servidor. Portanto, não é zero-access: quem controla o servidor/volume de chaves pode descriptografar.
- `data/web/inc/init_db.inc.php` define `mailbox.password`, `mailbox.attributes`, `custom_attributes`, `app_passwd`, `tfa`, OAuth e ACLs. Esse é o ponto natural para metadados de chaves, estado de ativação e políticas por domínio/mailbox.
- `data/conf/dovecot/auth/passwd-verify.lua` autentica IMAP/SMTP/Sieve chamando o backend web por HTTPS interno. Isso pode ser estendido para devolver campos `userdb_*` do Dovecot no futuro.
- SOGo é o webmail/groupware atual, configurado por `data/conf/sogo/sogo.conf`. Ele é ótimo para compatibilidade, mas não é um cliente zero-access completo, porque processa corpo de e-mail no servidor.
- Rspamd/quarentena dependem de ler conteúdo antes da entrega. Isso continua possível para e-mail externo antes da criptografia em repouso, mas não para conteúdo E2EE já criptografado.

## Pesquisa e referências usadas

- Proton descreve zero-access como armazenamento criptografado onde apenas o usuário possui a chave para acessar mensagens e anexos. Também separa mensagens internas E2EE, mensagens externas via TLS, PGP e mensagens protegidas por senha: https://proton.me/support/proton-mail-encryption-explained
- Proton explica que as chaves privadas são protegidas pela senha do usuário e que mensagens externas podem ser zero-access em repouso sem serem E2EE no provedor remoto: https://proton.me/blog/protonmail-threat-model
- Proton Bridge mostra o padrão de compatibilidade recomendado: um app local faz criptografia/descriptografia e expõe IMAP/SMTP local para clientes tradicionais: https://proton.me/blog/bridge-security-model
- Tuta enfatiza criptografia client-side antes de sair do dispositivo e chave privada criptografada pela senha do usuário: https://tuta.com/blog/zero-knowledge-architecture
- Tuta documenta que PGP não cobre assunto, não facilita troca de algoritmos e não resolve todos os requisitos modernos: https://tuta.com/encryption
- Dovecot Mail Crypt suporta chaves globais e chaves por usuário/pasta; para zero-access, o caminho relevante é chave por usuário criptografada por segredo derivado do usuário: https://doc.dovecot.org/main/core/plugins/mail_crypt.html
- Autocrypt automatiza distribuição de chaves OpenPGP por headers e recomenda criptografia oportunista sem quebrar workflows tradicionais: https://docs.autocrypt.org/level1.html
- Mailvelope confirma WKD, servidor de chaves próprio, OpenPGP em webmail e possibilidade de operar um diretório de chaves sob o próprio domínio: https://mailvelope.com/en/faq e https://keys.mailvelope.com/
- OpenPGP é padrão aberto para autenticação e criptografia de e-mail, com RFCs modernas como RFC 9580 e PGP/MIME: https://www.openpgp.org/about/

## Repositórios de referência locais

Foram clonados como referência, fora do Git deste fork:

- `vendor-reference/proton-webclients`: monorepo GPL-3.0 dos clientes web Proton. Ele usa Yarn Workspaces, mas deve ser tratado como biblioteca de ideias, não como base de produto. Pontos de estudo prioritários: `applications/mail`, `packages/mail`, `packages/mail-renderer`, `packages/sanitize`, `packages/encrypted-search`, `packages/key-transparency`, `packages/recovery-kit`, `packages/components` e `packages/shared`.
- `vendor-reference/proton-bridge`: Bridge GPL-3.0 em Go/QML. Pontos de estudo prioritários: `internal/bridge`, `internal/user`, `internal/vault`, `pkg/message`, `pkg/mime`, `pkg/keychain`, `pkg/ports`, `tests/imap_test.go`, `tests/smtp_test.go` e os cenários em `tests/features`.

Regras para usar esses repositórios:

- Não copiar grandes blocos de código sem decisão explícita de licenciamento e manutenção.
- Não importar padrões de produto Proton que dependem do backend Proton.
- Usar como referência de arquitetura, UX, testes, ameaça e nomenclatura.
- Quando uma ideia virar código nosso, registrar no PR qual arquivo inspirou a decisão.
- O produto novo deve usar Bun para os componentes web/API. Os repositórios Proton podem continuar com suas ferramentas originais apenas porque são material externo ignorado.

## Modelo de ameaça

### Deve proteger

- Operador do servidor lendo mensagens armazenadas.
- Vazamento de volumes Docker, backups, snapshots, dumps de banco ou Maildir.
- Comprometimento posterior do servidor tentando ler histórico antigo.
- Administrador de domínio ou superadmin visualizando conteúdo de usuários.
- Provedor SMTP externo passivo quando OpenPGP ou mensagem protegida por senha for usada.

### Não protege sozinho

- Dispositivo do usuário comprometido.
- JavaScript malicioso servido pelo próprio servidor comprometido no momento do login.
- Metadados necessários para e-mail: remetente, destinatário, horários, IPs de conexão, tamanho aproximado e roteamento.
- Assunto em e-mail PGP/MIME interoperável, salvo se adotarmos encapsulamento próprio para mensagens internas.
- Conteúdo entregue a provedores externos sem OpenPGP ou sem link protegido por senha.
- Spam/phishing em mensagens que chegam já E2EE, porque Rspamd verá apenas ciphertext.

## Decisão arquitetural recomendada

Construir em camadas:

1. Base de infraestrutura herdada: Postfix, Rspamd, MariaDB, Redis, nginx/php-fpm e partes úteis do admin podem ser reaproveitados, mas sem obrigação de preservar comportamento mailcow.
2. Zero-access em repouso: toda mensagem entregue ao mailbox é criptografada por usuário antes de ficar persistida.
3. Cliente web seguro novo: uma aplicação web moderna faz criptografia/descriptografia no navegador, usando WebCrypto e OpenPGP.js.
4. API criptográfica nova: o servidor armazena blobs criptografados, metadados mínimos, chaves públicas, chaves privadas criptografadas e pacotes de recuperação, mas nunca recebe chave privada em claro.
5. Bridge local opcional: app desktop expõe IMAP/SMTP em `localhost` para Thunderbird/Outlook/Apple Mail, descriptografando localmente como o Proton Bridge.
6. Compatibilidade externa: WKD, Autocrypt, OpenPGP, mensagens protegidas por senha e TLS forte.

Não recomendo tentar transformar SOGo no cliente zero-access principal. O esforço para fazer E2EE dentro de SOGo seria alto, frágil e ainda preso a um modelo de groupware que espera conteúdo legível no servidor. Como não precisamos preservar instalações mailcow existentes, a melhor decisão é remover SOGo do caminho crítico e criar um cliente seguro separado.

## Componentes propostos

### `zero-web`

Cliente web primário.

Responsabilidades:

- Login com senha de conta.
- Derivar chave de desbloqueio localmente com Argon2id ou WebCrypto PBKDF2 temporariamente, preferindo Argon2id via WASM.
- Baixar chave privada criptografada.
- Descriptografar chave privada apenas no navegador.
- Listar mensagens via API usando metadados mínimos.
- Descriptografar corpo/anexos localmente.
- Compor mensagens com OpenPGP.js.
- Publicar chaves públicas no diretório local.
- Mostrar estado de segurança por destinatário: local E2EE, OpenPGP verificado, Autocrypt oportunista, senha externa, TLS-only.

Stack sugerida:

- Bun como runtime e gerenciador.
- TypeScript.
- Vite ou SvelteKit/React conforme preferência do fork.
- OpenPGP.js para PGP/MIME e interoperabilidade.
- WebCrypto para envelopes internos e derivação auxiliar.
- Testes com Bun test e Playwright.

Plano de telas do MVP:

- Login e desbloqueio da chave.
- Onboarding criptográfico com geração de chave, frase de recuperação e verificação.
- Inbox com lista por remetente, data, estado criptográfico, anexos e flags.
- Leitura com renderização segura de HTML, anexos, cabeçalhos técnicos e fingerprint.
- Composer com destinatários, assunto protegido quando possível, anexos, assinatura e seletor de modo de envio.
- Contatos/chaves com busca local, WKD, Autocrypt, importação manual e pinning.
- Configurações de segurança com rotação de senha, rotação de chave, revogação e exportação de recuperação.
- Portal de mensagem protegida por senha para destinatários externos.

Regras de UX:

- O usuário sempre deve ver o estado real de segurança antes de enviar.
- Nenhum botão deve prometer E2EE quando o destino é TLS-only.
- Mudança de chave de contato deve interromper envio automático até o usuário confirmar.
- Perda de recuperação deve ser tratada como incidente de segurança, não como aviso secundário.
- A tela de leitura deve bloquear imagens remotas por padrão.

### `zero-api`

API HTTP interna/externa para o cliente seguro.

Responsabilidades:

- Autenticação e sessão.
- Nunca receber senha derivada reutilizável como chave de criptografia.
- Guardar chave pública por endereço.
- Guardar chave privada criptografada por senha do usuário.
- Tratar senha como material de proteção da chave privada, não como semente determinística da chave privada.
- Guardar blobs de mensagem criptografados.
- Guardar índice mínimo: mailbox, folder, flags, datas, tamanho, remetente/destinatários e assunto conforme política.
- Endpoints para upload/download de anexos criptografados.
- Endpoints WKD.
- Endpoints de key transparency.
- Endpoints para recuperação de conta, rotação e revogação de chaves.

Stack sugerida:

- Serviço separado no `docker-compose.yml`.
- Bun + TypeScript ou Go/Rust se quiser reduzir superfície JS no servidor. Como a instrução do projeto pede Bun, usar Bun para API nova é coerente.
- Banco MariaDB atual para metadados, com evolução de schema versionada para esta nova aplicação.
- Volume separado para blobs grandes criptografados, ou S3/R2 compatível no futuro.

Contratos iniciais da API:

- `GET /health`: healthcheck sem tocar segredos.
- `POST /auth/login`: autentica e cria sessão.
- `GET /crypto/bootstrap`: retorna salts, KDF params, chave pública atual, chave privada criptografada e estado de recuperação.
- `POST /crypto/keys`: cadastra primeira chave ou nova versão de chave.
- `POST /crypto/password/reencrypt`: troca de senha com senha atual disponível no cliente; recebe apenas novo envelope criptografado da mesma chave privada.
- `POST /crypto/password/reset`: reset sem senha atual; revoga identidade criptográfica anterior e cadastra nova chave, tornando histórico antigo ilegível sem recuperação.
- `POST /crypto/recovery`: cadastra pacote de recuperação.
- `GET /keys/local/:address`: resolve chave pública local.
- `GET /keys/wkd/:address`: endpoint interno de montagem WKD.
- `GET /events/key/:address`: retorna cadeia pública de eventos de chave para auditoria.
- `GET /events/key/:address/verify`: verifica hash e encadeamento da cadeia pública de eventos de chave.
- `GET /events/key/:address/checkpoint`: retorna resumo compacto da cadeia para pinning do cliente.
- `GET /mail/folders`: lista folders.
- `GET /mail/messages?folder=&cursor=`: lista metadados paginados.
- `GET /mail/messages/:id/blob`: retorna ciphertext da mensagem.
- `POST /mail/messages`: cria mensagem local ou fila de envio externo.
- `POST /mail/attachments`: faz upload de anexo criptografado.
- `GET /mail/attachments/:id`: baixa anexo criptografado.
- `POST /events/key`: registra evento de key transparency.

Regras de API:

- Nenhum endpoint aceita chave privada em claro.
- Nenhum endpoint aceita senha atual, nova senha, hash de senha ou derivado reutilizável.
- Nenhum endpoint retorna corpo descriptografado.
- Troca de senha autenticada exige prova client-side de posse da chave privada antiga já desbloqueada, sem enviar a chave privada ao servidor.
- Reset sem senha atual deve sempre retornar estado explícito de perda de acesso ao histórico antigo, salvo quando houver pacote de recuperação válido.
- Logs devem registrar IDs, status e tamanhos aproximados, nunca assunto claro, corpo, nomes de anexos ou material de chave.
- Todas as respostas sensíveis precisam de `Cache-Control: no-store`.
- Sessões web devem ser curtas, renováveis e revogáveis por dispositivo.

### `zero-delivery`

Camada entre Postfix/Rspamd/Dovecot e armazenamento.

Duas opções:

Opção A, fase inicial mais simples: Dovecot Mail Crypt por usuário.

- Trocar chave global por chave por usuário/pasta.
- Dovecot recebe senha do usuário no login e usa `crypt_user_key_password`.
- Limitação: e-mail recebido por LMTP precisa ser salvo sem a senha do usuário online. Para entrega offline, Dovecot precisa de chave pública do usuário ou chave de usuário acessível ao servidor. Isso pode virar apenas criptografia em repouso operacional, não zero-access completo, se mal desenhado.

Opção B, recomendada para o produto final: delivery encryptor próprio.

- Postfix entrega a um serviço LMTP/SMTP interno `zero-delivery`.
- Rspamd roda antes do `zero-delivery` para e-mails externos em claro.
- `zero-delivery` resolve destinatários locais, busca chaves públicas, cria envelope criptografado para cada destinatário e grava no store.
- Dovecot/SOGo deixam de ser a fonte principal para o cliente zero-access.
- Não gravar cópia legível em Dovecot/SOGo no modo principal.

Recomendação: usar a opção B como arquitetura final. A opção A serve apenas para entender limites do Dovecot Mail Crypt, não como fase de produto.

Pipeline final de entrega:

1. Postfix recebe SMTP público.
2. Rspamd analisa mensagem em claro quando ela veio sem E2EE.
3. Postfix roteia destinatários locais para `zero-delivery`.
4. `zero-delivery` consulta destinatários, aliases e políticas.
5. Para cada destinatário final, monta envelope independente.
6. O corpo MIME canônico vira ciphertext.
7. O assunto é criptografado para armazenamento; o cabeçalho externo pode ser descartado, reduzido ou substituído por texto genérico conforme política.
8. Blobs são gravados no store.
9. Metadados mínimos são gravados no MariaDB.
10. Evento de entrega é emitido para notificações.

Casos especiais:

- Alias para múltiplos destinatários gera uma cópia criptográfica por destinatário.
- Catch-all deve exigir chave ativa do mailbox final.
- Redirecionamento para externo não descriptografa conteúdo; se precisar encaminhar legível, a ação deve ocorrer no cliente.
- BCC local deve preservar separação de metadados entre destinatários.
- Quarentena deve acontecer antes da criptografia ou ser criptografada para destinatário e caixa administrativa específica.
- DSN/bounce não deve incluir corpo original em claro.

### `zero-bridge`

Bridge desktop opcional.

Responsabilidades:

- Rodar só em `localhost`.
- Fazer login na API.
- Manter chave privada só em memória ou no keychain do sistema criptografada.
- Expor IMAP/SMTP local para clientes tradicionais.
- Converter mensagens criptografadas do servidor para MIME claro localmente.
- Criptografar envio antes de subir para o servidor.

Stack sugerida:

- Go ou Rust para distribuição desktop simples.
- GopenPGP ou biblioteca OpenPGP madura.
- Publicar depois do MVP web, não antes.

O que estudar no Proton Bridge:

- Modelo de `vault.enc` para guardar segredos locais.
- Uso de keychain do sistema por plataforma.
- Servidores IMAP/SMTP apenas locais.
- Estratégia de cache local e limpeza.
- Testes de IMAP/SMTP orientados a comportamento.
- Modelo de atualização assinado, que pode ser simplificado na primeira versão.

Escopo da nossa bridge:

- Fase 1 da bridge: Linux apenas, sem auto-update, localhost, uma conta.
- Fase 2: múltiplas contas, keychain, cache seletivo e empacotamento.
- Fase 3: Windows/macOS e update assinado.

### Diretório de chaves

Implementar:

- WKD para `https://openpgpkey.DOMINIO/.well-known/openpgpkey/...` e modo direct/advanced.
- Autocrypt header em mensagens enviadas.
- Key discovery interno por API para usuários locais.
- Key transparency append-only para reduzir risco de servidor substituir chaves públicas silenciosamente.
- Verificação manual por fingerprint para contatos sensíveis.

Estados de confiança:

- `local_verified`: usuário da mesma instância com key transparency consistente.
- `manual_verified`: fingerprint verificado manualmente.
- `wkd_verified`: chave obtida por WKD via HTTPS válido, ainda sujeita a troca pelo domínio.
- `autocrypt_seen`: chave vista em header Autocrypt, oportunista.
- `imported_unverified`: chave importada sem verificação.
- `conflict`: chave mudou ou múltiplas fontes discordam.

### Mensagens protegidas por senha

Para destinatários sem chave pública:

- Gerar mensagem criptografada simétrica no cliente.
- Enviar e-mail externo com link para portal público.
- O segredo não pode estar no servidor; usar fragmento URL `#secret` ou senha compartilhada fora de banda.
- Definir expiração, limite de tentativas, revogação e política de download.
- Portal público deve usar WebCrypto e nunca enviar a senha ao servidor.

Formato recomendado:

- O servidor armazena somente ciphertext, salt público, KDF params, data de expiração e contador de tentativas.
- A URL carrega identificador no path e segredo no fragmento: `/secure-message/:id#secret`.
- Como fragmento não é enviado em HTTP, o servidor não recebe o segredo.
- Se o remetente preferir senha fora de banda, o fragmento pode conter apenas salt auxiliar e a senha digitada localmente completa a derivação.
- Respostas do portal devem usar `no-store`, CSP estrita e sem analytics.

## Topologia Docker alvo

Serviços mantidos ou reaproveitados:

- `mariadb`: metadados, usuários, chaves públicas, chaves privadas criptografadas e índices mínimos.
- `redis`: sessões, filas leves, rate limits e eventos transitórios.
- `postfix`: SMTP público inbound/outbound.
- `rspamd`: antispam antes da criptografia quando houver conteúdo claro.
- `nginx`: TLS público, rotas web, API e WKD.
- `acme`: certificados.
- `unbound`: DNS local.

Serviços novos:

- `zero-api`: API Bun/TypeScript.
- `zero-web`: build estático do cliente seguro, servido por nginx ou container próprio.
- `zero-delivery`: LMTP/SMTP interno para criptografar e persistir mensagens.
- `zero-worker`: filas de envio externo, notificações, limpeza de expiração e tarefas de key transparency.
- `zero-blob`: volume ou serviço simples de blobs criptografados.

Serviços fora do caminho principal:

- `dovecot`: remover do caminho de leitura/escrita principal; manter temporariamente só enquanto a infraestrutura é desmontada.
- `sogo`: remover do produto principal.
- `clamd`: avaliar depois; antivírus de anexo antes da criptografia é útil para inbound externo, mas não pode ver E2EE.

Volumes novos:

- `zero-blob-vol-1`: ciphertext de mensagens e anexos.
- `zero-api-config-vol-1`: configuração não secreta.
- `zero-worker-state-vol-1`: estado operacional descartável.

Segredos:

- Segredo de sessão do servidor.
- Credenciais MariaDB/Redis.
- Chave de assinatura de releases do web client, se adotarmos verificação.
- Nenhum segredo do servidor deve permitir descriptografar mailbox de usuário.

## Envelope criptográfico interno

Objetivo: separar formato interno eficiente de interoperabilidade OpenPGP externa.

Mensagem interna recomendada:

- `version`: versão do envelope.
- `message_id`: ID lógico.
- `sender_signing_key_id`: chave de assinatura do remetente.
- `recipients`: lista de envelopes de chave, um por destinatário.
- `content_alg`: algoritmo simétrico.
- `content_nonce`: nonce.
- `ciphertext`: corpo MIME canônico criptografado.
- `aad`: metadados autenticados não secretos.
- `signature`: assinatura do remetente sobre envelope e metadados autenticados.

Cada recipient envelope:

- `address`
- `recipient_key_id`
- `wrapped_content_key`
- `wrap_alg`

Algoritmos iniciais:

- OpenPGP.js para mensagens OpenPGP e chaves compatíveis.
- AES-256-GCM para blobs internos quando não estivermos usando PGP/MIME puro.
- Argon2id para proteger chave privada com senha.
- SHA-256/BLAKE3 para hashes de ciphertext e integridade operacional.

Regras:

- O servidor pode validar estrutura, tamanho, destinatários e assinatura pública quando possível.
- O servidor nunca unwrap da content key.
- Anexos grandes têm content keys próprias, também encapsuladas no envelope da mensagem.
- Metadados usados em lista devem ser minimizados e, quando possível, criptografados em campos separados.

## Mudanças de banco propostas

Adicionar tabelas novas, sem sobrecarregar `mailbox.attributes` para material criptográfico importante:

### `zero_user_keys`

- `username`
- `address`
- `primary_key_id`
- `public_key_armored`
- `encrypted_private_key`
- `private_key_kdf`
- `private_key_kdf_params`
- `key_version`
- `status`
- `rotation_mode`
- `previous_key_id`
- `created`
- `rotated`
- `revoked`

`rotation_mode` diferencia criação inicial, troca de senha com recriptografia da mesma chave privada, reset destrutivo sem senha atual, recriptografia via recuperação e rotação criptográfica real. `previous_key_id` encadeia as versões para auditoria e key transparency.

### `zero_recipient_keys`

- `address`
- `source`
- `public_key_armored`
- `fingerprint`
- `trust_level`
- `first_seen`
- `last_seen`
- `last_verified`
- `expires`
- `status`

Fontes: `local`, `wkd`, `autocrypt`, `manual`, `keyserver`.

### `zero_messages`

- `id`
- `mailbox`
- `folder`
- `rfc822_message_id`
- `thread_id`
- `direction`
- `encrypted_blob_ref`
- `encrypted_subject`
- `subject_search_hash`
- `from_addr`
- `to_addrs`
- `cc_addrs`
- `bcc_addrs`
- `date_header`
- `received_at`
- `size`
- `flags`
- `encryption_state`
- `spam_state`

### `zero_attachments`

- `id`
- `message_id`
- `encrypted_blob_ref`
- `encrypted_name`
- `mime_type`
- `size`
- `sha256_ciphertext`

### `zero_key_events`

- `id`
- `address`
- `event_type`
- `fingerprint`
- `event_payload`
- `previous_event_hash`
- `event_hash`
- `created`

Eventos mínimos: `created`, `rotated`, `revoked`, `recovered`, `verified`, `password_reencrypted` e `password_reset`.

Estado implementado no `zero-api`: criação de chave, troca de senha com recriptografia e reset destrutivo já registram eventos sem incluir chave privada criptografada, senha, KDF params ou envelopes privados. O store calcula `previous_event_hash` e `event_hash` por endereço para formar a primeira cadeia local de auditoria, já existe verificação de integridade dessa cadeia e um checkpoint compacto para pinning do cliente.

Essa tabela prepara key transparency local.

### `zero_recovery`

- `username`
- `method`
- `encrypted_recovery_packet`
- `public_hint`
- `created`
- `used`
- `revoked`

Métodos: frase de recuperação, chave de recuperação impressa, guardião/admin split-key opcional, dispositivo autorizado.

## Fluxos principais

### Criação de mailbox

1. Admin cria mailbox na nova aplicação.
2. Usuário faz primeiro login no `zero-web`.
3. Browser gera par OpenPGP ou envelope interno.
4. Browser deriva chave de proteção a partir da senha.
5. Browser criptografa chave privada.
6. API salva chave pública e chave privada criptografada.
7. API publica WKD automaticamente se domínio permitir.
8. Usuário recebe frase/código de recuperação.

Importante: a senha não gera a chave privada de forma determinística. A chave privada deve ser gerada com aleatoriedade criptográfica no cliente; a senha protege o envelope criptografado dessa chave.

### Login

1. Usuário autentica no `zero-api`.
2. API retorna salt e parâmetros KDF.
3. Browser deriva chave local.
4. Browser baixa e descriptografa chave privada.
5. Chave privada fica apenas em memória, ou em armazenamento local criptografado com autorização explícita.

### Troca de senha com senha atual

1. Usuário informa senha atual e nova senha no cliente.
2. Browser usa a senha atual para abrir o envelope da chave privada.
3. Browser deriva nova chave de proteção a partir da nova senha.
4. Browser recriptografa a mesma chave privada com o novo envelope.
5. Browser envia ao `zero-api` somente `reencryptedPrivateKey`, novos parâmetros KDF e uma prova assinada pela chave privada antiga desbloqueada.
6. API substitui o envelope ativo e mantém a mesma chave pública e o mesmo `primaryKeyId`.
7. Mensagens antigas continuam legíveis porque a chave privada real não mudou.

### Reset de senha sem senha atual

1. Usuário, admin ou fluxo de recuperação inicia reset sem a senha atual.
2. UI informa de forma bloqueante que o histórico antigo será perdido se não houver pacote de recuperação.
3. Browser gera novo par de chaves e novo envelope protegido pela nova senha.
4. API revoga a chave ativa anterior.
5. API publica a nova chave pública local.
6. Entregas futuras usam a nova chave.
7. Mensagens antigas criptografadas para a chave anterior ficam ilegíveis nesse estado.

### Recebimento externo

1. Postfix recebe SMTP.
2. Rspamd analisa conteúdo em claro enquanto ainda é possível.
3. `zero-delivery` busca chave pública do destinatário.
4. Mensagem é normalizada para MIME canônico.
5. Corpo e anexos são criptografados para o destinatário.
6. Metadados mínimos são salvos.
7. Nenhuma cópia legível é gravada em Dovecot/SOGo no modo principal.

### Envio para usuário local

1. `zero-web` busca chave pública local do destinatário.
2. Browser criptografa e assina antes de enviar.
3. API salva cópia em `Sent` do remetente.
4. API entrega blob criptografado ao destinatário local sem descriptografar.
5. Postfix não precisa ver o corpo para mensagens totalmente locais.

### Envio para externo com OpenPGP

1. Cliente consulta chaves por cache local, WKD, Autocrypt e contatos.
2. Se chave confiável existir, browser gera PGP/MIME assinado e criptografado.
3. Servidor envia via Postfix como SMTP normal.
4. Cópia enviada é armazenada zero-access.

### Envio para externo sem chave

1. UI oferece TLS-only ou mensagem protegida por senha.
2. Se usuário escolhe senha/link, browser criptografa conteúdo.
3. Servidor manda notificação com link.
4. Destinatário abre portal e descriptografa no navegador.

## Roteiro granular de execução

### Épico A: fundação do fork

Tarefas:

- Criar mapa dos containers atuais e marcar cada um como `manter`, `substituir`, `remover` ou `avaliar`.
- Criar `docs/architecture/current-mailcow-map.md` com fluxo SMTP inbound, SMTP outbound, auth, web admin e volumes.
- Criar `docs/architecture/target-zero-access-map.md` com a nova topologia.
- Definir nomes finais dos serviços no `docker-compose.yml`.
- Criar arquivo de configuração zero-access com valores obrigatórios e falha explícita se faltar segredo operacional.
- Adicionar teste que roda `docker compose config`.

Saída esperada:

- Decisão objetiva sobre Postfix, Rspamd, nginx, MariaDB, Redis, Dovecot e SOGo.
- Nenhuma dependência conceitual de upgrade de mailcow original.

### Épico B: pacote Bun do `zero-api`

Tarefas:

- Criar workspace Bun isolado em `services/zero-api`.
- Criar healthcheck.
- Criar conexão MariaDB.
- Criar conexão Redis.
- Criar logger com redaction obrigatória.
- Criar mecanismo de migração/evolução de schema.
- Criar testes unitários para config, redaction e healthcheck.

Saída esperada:

- Container `zero-api` sobe.
- Endpoint `/health` responde.
- Logs não vazam env sensível.

### Épico C: pacote Bun do `zero-web`

Tarefas:

- Criar app web em `services/zero-web`.
- Definir design system mínimo.
- Implementar login visual sem criptografia real.
- Implementar store de sessão.
- Adicionar Playwright para login mockado.
- Adicionar build estático servido pelo nginx.

Saída esperada:

- Usuário abre a UI real, não uma landing page.
- Build roda com Bun.
- Teste E2E básico passa.

### Épico D: chaves do usuário

Tarefas:

- Implementar geração de chave no browser.
- Implementar KDF com parâmetros versionados.
- Salvar chave pública e chave privada criptografada.
- Implementar recuperação.
- Implementar rotação de senha autenticada.
- Implementar reset sem senha atual como nova identidade criptográfica, com revogação explícita da chave anterior.
- Adaptar o painel do mailcow para exibir duas opções na troca de senha: preservar histórico com senha atual ou resetar cofre e perder histórico antigo.
- Implementar endpoint WKD para chave pública.
- Adicionar testes com duas contas.

Saída esperada:

- Dump do banco não contém chave privada em claro.
- Usuário consegue sair, entrar e desbloquear a mesma chave.
- WKD retorna chave pública correta.

### Épico E: mailbox criptografado interno

Tarefas:

- Implementar `zero_messages`. Iniciado no `zero-api` com armazenamento de metadados criptográficos, `folder`, `created` e persistência JSONL temporária.
- Implementar blob store. Concluído no `zero-api` para upload/download de ciphertext com `Cache-Control: no-store`.
- Implementar envelope interno.
- Implementar envio local-local.
- Implementar listagem de inbox. Iniciado no `zero-api` com `GET /mail/messages?recipient=&folder=&cursor=&limit=`, paginação por cursor, filtro por destinatário/pasta e `GET /mail/folders?recipient=` com contagens por pasta.
- Implementar leitura e descriptografia no browser.
- Implementar anexos pequenos. Iniciado no `zero-api` com metadados criptografados, validação de hash do ciphertext, `POST /mail/attachments`, `GET /mail/attachments/:id` e `GET /mail/messages/:id/attachments`.
- Adicionar teste que procura texto claro no banco, blobs e logs.

Saída esperada:

- Alice envia para Bob local.
- Bob lê.
- Servidor não contém corpo/anexo em claro.

### Épico F: SMTP inbound com `zero-delivery`

Tarefas:

- Criar serviço `zero-delivery`.
- Receber LMTP ou SMTP interno do Postfix.
- Resolver destinatários locais.
- Integrar Rspamd antes da persistência.
- Criptografar inbound externo para chave pública do destinatário.
- Persistir metadados mínimos.
- Tratar alias simples.
- Adicionar teste SMTP real com mensagem externa.

Saída esperada:

- Mensagem SMTP externa aparece no `zero-web`.
- Conteúdo fica criptografado em repouso.
- Rspamd ainda consegue analisar inbound claro antes da criptografia.

### Épico G: envio externo

Tarefas:

- Implementar fila de envio no `zero-worker`.
- Implementar envio TLS-only via Postfix.
- Implementar OpenPGP externo quando chave existir.
- Implementar Autocrypt outbound.
- Implementar cópia enviada zero-access.
- Implementar status de entrega.

Saída esperada:

- Usuário local envia para domínio externo.
- Cópia em `Sent` fica criptografada.
- UI mostra se foi E2EE/OpenPGP ou TLS-only.

### Épico H: hardening e bridge

Tarefas:

- Revisar CSP, headers e caching.
- Criar key transparency inicial.
- Criar alertas de mudança de chave.
- Fazer fuzzing de MIME.
- Estudar `vendor-reference/proton-bridge`.
- Criar prova de conceito de bridge Linux localhost.

Saída esperada:

- Threat model atualizado.
- Primeiro cliente IMAP tradicional lê via bridge, não via Dovecot público.

## Fases de implementação

### Fase 0: ruptura arquitetural e baseline

Entregáveis:

- Documentar exatamente o que o mailcow atual cifra e o que não cifra.
- Decidir quais componentes herdados continuam no produto e quais saem do caminho crítico.
- Remover a exigência de upgrade in-place de instalações mailcow existentes.
- Garantir que backups da nova aplicação nunca incluam chaves úteis em claro.
- Adicionar configuração global simples: `ZERO_ACCESS_REQUIRED=y`.

Critérios de aceite:

- `docker compose config` válido.
- Testes de configuração passam para a nova topologia.
- O plano de produto declara explicitamente que não há retrocompatibilidade com instalações mailcow existentes.

### Fase 1: modelo de chaves e cadastro

Entregáveis:

- Evolução de schema das tabelas `zero_*`.
- API para publicar e consultar chave pública local.
- UI de primeiro login para gerar chave.
- UI de recuperação.
- WKD read-only para domínios locais.

Critérios de aceite:

- Chave privada nunca trafega em claro para o servidor.
- Dump do banco contém apenas chave privada criptografada.
- Usuário consegue rotacionar senha sem perder chave.
- Recuperação é testada em conta nova.

### Fase 2: cliente web zero-access MVP

Entregáveis:

- Inbox, leitura, composição e envio local-local.
- Criptografia e assinatura no browser.
- Upload/download de anexos criptografados.
- Estados de segurança na composição.
- Testes unitários de envelope criptográfico.
- Testes E2E com duas contas locais.

Critérios de aceite:

- Mensagem local-local nunca aparece em claro no banco, volume de blobs ou logs.
- Reload do browser mantém acesso após login.
- Busca inicial pode ser limitada a metadados.

### Fase 3: delivery externo zero-access

Entregáveis:

- Serviço `zero-delivery`.
- Integração Postfix depois do Rspamd.
- Criptografia automática de mensagem recebida para chave pública do destinatário.
- Política para aliases, catch-all, grupos e encaminhamentos.
- Quarentena antes da criptografia, ou quarentena criptografada para destinatário quando o modo estrito exigir.

Critérios de aceite:

- E-mail externo recebido fica criptografado em repouso.
- Rspamd continua funcionando para mensagens externas em claro.
- Alias para múltiplos destinatários gera envelope separado por destinatário.

### Fase 4: interoperabilidade OpenPGP

Entregáveis:

- WKD completo.
- Autocrypt inbound/outbound.
- Importação manual de chaves.
- Verificação por fingerprint.
- PGP/MIME para externos.

Critérios de aceite:

- Thunderbird + OpenPGP consegue trocar mensagens com usuário local.
- Mailvelope consegue descobrir chave via WKD.
- Mudança de chave dispara aviso de confiança.

### Fase 5: modo senha externa

Entregáveis:

- Portal público de mensagem protegida por senha.
- Links com segredo no fragmento ou senha fora de banda.
- Expiração, revogação, limite de tentativas.
- Auditoria sem registrar segredo.

Critérios de aceite:

- Servidor não consegue descriptografar mensagem protegida por senha.
- Link expirado não revela metadados sensíveis além do mínimo.

### Fase 6: interoperabilidade IMAP/SMTP via bridge local

Entregáveis:

- `zero-bridge` desktop.
- IMAP/SMTP apenas em localhost.
- Login com API.
- Cache local criptografado opcional.
- Empacotamento para Linux primeiro.

Critérios de aceite:

- Thunderbird lê e envia por bridge.
- Chaves privadas não são gravadas em claro.
- Porta não escuta fora de localhost.

### Fase 7: endurecimento, auditoria e lançamento

Entregáveis:

- Threat model público.
- Testes de regressão criptográfica.
- Fuzzing de parsing MIME.
- Revisão de logs para vazamento de conteúdo.
- Guia de instalação limpa e guia de importação opcional.
- Guia de perda de senha e recuperação.
- Auditoria externa antes de declarar estabilidade.

Critérios de aceite:

- Backup restaurado não permite ler conteúdo sem senha/chave do usuário.
- Admin não consegue exportar mensagem em claro.
- Rotação de chave e revogação documentadas e testadas.

## Políticas difíceis que precisam de decisão

### Assunto

Opções:

- Compatibilidade PGP: assunto fica em claro ou substituído por texto genérico.
- Modelo Proton-like: assunto pode ser armazenado criptografado, mas cabeçalhos SMTP externos ainda expõem assunto quando enviado sem encapsulamento.
- Modelo Tuta-like interno: assunto interno sempre criptografado e assunto SMTP externo vira texto genérico.

Recomendação: assunto criptografado para mensagens internas e armazenadas; para SMTP externo, oferecer texto genérico configurável.

### Busca

Busca server-side em conteúdo quebra zero-access.

Opções:

- Busca local no browser após baixar índices criptografados.
- Índice criptografado por usuário, atualizado no cliente.
- Busca apenas por metadados no MVP.

Recomendação: MVP com busca por metadados; depois índice local criptografado.

### Antispam

Rspamd precisa ver conteúdo. Para e-mail externo, pode rodar antes da criptografia em repouso. Para E2EE real, verá apenas ciphertext.

Recomendação: aceitar essa limitação e criar heurísticas por metadados para mensagens já criptografadas.

### Filtros Sieve

Filtros por corpo não funcionam sem conteúdo em claro no servidor.

Recomendação: manter filtros por metadados no servidor e mover filtros por conteúdo para o cliente.

### Encaminhamento

Encaminhar automaticamente e-mail zero-access para externo pode exigir descriptografia, o que o servidor não tem.

Recomendação: permitir encaminhamento server-side apenas de mensagem externa antes da criptografia ou de ciphertext; para encaminhar conteúdo legível, exigir cliente/bridge autorizado.

### Recuperação de senha

Reset tradicional de senha é incompatível com chaves protegidas pela senha antiga.

Recomendação:

- Painel do mailcow deve oferecer duas ações separadas quando uma senha for alterada.
- Trocar senha com senha atual: cliente recriptografa a mesma chave privada com a nova senha e preserva acesso ao histórico.
- Trocar senha sem senha atual: cliente cria nova identidade criptográfica; servidor revoga a chave antiga; histórico antigo fica perdido sem recuperação.
- Reset com pacote de recuperação válido pode abrir a chave privada antiga no cliente e seguir o fluxo de recriptografia.
- UX precisa deixar claro que perder senha e recuperação significa perda real de histórico.

## Reaproveitamento do mailcow neste fork

### Postfix

Mudanças:

- Adicionar transporte interno para `zero-delivery` por domínio/mailbox.
- Preservar `smtpd_milters = inet:rspamd:9900` antes da criptografia para inbound externo.
- Criar mapas SQL para domínios e mailboxes da nova aplicação.
- Garantir que BCC/footers/disclaimers não tentem modificar conteúdo E2EE.

### Dovecot

Mudanças:

- Remover dependência de chave global como alegação de segurança.
- Remover Dovecot do caminho principal de leitura/escrita zero-access.
- Usar Dovecot apenas como referência técnica ou serviço auxiliar se ele não enfraquecer o modelo de ameaça.
- A interoperabilidade IMAP deve acontecer via bridge local, não por IMAP aberto no servidor.

### SOGo

Mudanças:

- Remover SOGo do caminho crítico do produto zero-access.
- Não tentar adaptar recursos server-side incompatíveis como full-text search de corpo, filtros por corpo e delegação com leitura server-side.
- Reavaliar calendário/contatos depois, como módulos criptografados próprios ou integração separada.

### Rspamd

Mudanças:

- Rodar antes de `zero-delivery`.
- Não armazenar corpo em quarentena quando modo estrito exigir zero-access; ou criptografar quarentena para o destinatário/admin designado.
- Ajustar treinamento spam/ham: cliente pode reenviar ciphertext? Melhor criar fluxo que submete amostras explicitamente pelo usuário.

### Admin PHP

Mudanças:

- Adicionar configuração por domínio para políticas criptográficas, sem modo não criptografado como produto principal.
- Adicionar estado por mailbox: sem chave, chave ativa, recuperação pendente, chave revogada.
- Impedir admin de acessar conteúdo.
- Expor auditoria de eventos de chave sem revelar material secreto.

## Roadmap de testes

### Testes unitários

- Derivação de chave com vetores fixos.
- Criptografia/decriptografia de envelope.
- Rotação de senha.
- Rotação de chave.
- Validação WKD.
- Parser Autocrypt.
- Normalização MIME.

### Testes de integração

- Criar domínio e duas mailboxes.
- Primeiro login gera chaves.
- Local A envia para local B.
- B lê no navegador.
- Dump do banco e blobs não contêm texto claro.
- E-mail externo chega via SMTP e fica criptografado em repouso.
- Alias entrega envelopes diferentes.
- Reset de senha com recuperação.

### Testes E2E

- Playwright para fluxo web.
- Cliente externo OpenPGP enviando para WKD local.
- Mailvelope ou Thunderbird com chave descoberta.
- Bridge com Thunderbird quando existir.

### Testes de segurança

- Verificar logs de nginx, php-fpm, postfix, dovecot, rspamd e zero-api contra vazamento de conteúdo.
- Fuzzing de MIME e anexos.
- Teste de substituição de chave pública.
- Teste de downgrade para TLS-only.
- Teste de backup restaurado sem senha do usuário.

## Métricas de pronto

MVP zero-access:

- Mensagem local-local E2EE funcionando no web client.
- Mensagem externa recebida armazenada criptografada para o usuário.
- Chave privada protegida por senha do usuário e recuperação criada.
- WKD publicando chaves locais.
- Admin não consegue ler corpo/anexos por UI, banco, blobs ou Maildir.

Beta:

- OpenPGP externo completo.
- Mensagem protegida por senha.
- Documentação de limitações.
- Testes E2E automatizados.

Estável:

- Bridge desktop.
- Key transparency.
- Auditoria externa.
- Rotação e recuperação maduras.
- Guias operacionais para backup, restore, perda de senha e resposta a incidente.

## Riscos principais

- Servir cliente web pelo mesmo servidor que pode estar comprometido permite ataque de JavaScript malicioso. Mitigação: builds reproduzíveis, assinatura/subresource integrity, apps desktop/mobile no futuro e transparência de releases.
- Perda de senha pode significar perda real de histórico. Mitigação: recuperação obrigatória e UX honesta.
- SOGo e IMAP tradicional criam expectativa errada. Mitigação: removê-los do caminho principal e oferecer IMAP apenas via bridge local.
- Antispam e busca perdem poder em E2EE. Mitigação: processar antes da criptografia quando legítimo e mover recursos sensíveis para cliente.
- OpenPGP tem limitações de assunto e metadados. Mitigação: encapsulamento interno próprio para usuários locais e UI que explique estados.
- Key substitution pelo servidor é um risco central. Mitigação: key transparency, fingerprints, pinning por contato e alertas de rotação.

## Próxima etapa recomendada

Implementar a Fase 0 e preparar a Fase 1:

1. Criar `ZERO_ACCESS_REQUIRED=y` no gerador de config da nova aplicação.
2. Adicionar evolução inicial de schema das tabelas `zero_*`.
3. Criar serviço `zero-api` mínimo com Bun e endpoint de healthcheck.
4. Criar testes que provam que a nova topologia sobe sem depender de Dovecot/SOGo como caminho principal.
5. Criar uma prova de conceito web que gera chave no navegador, salva chave pública e salva chave privada criptografada.

Essa sequência reduz risco porque cria a fundação criptográfica correta antes de tocar na entrega de e-mails, sem carregar a dívida de retrocompatibilidade do mailcow original.
