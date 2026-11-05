# Autenticação JWT com Express

[![CI](https://github.com/sidsidoso/autenticacao-jwt-express/actions/workflows/ci.yml/badge.svg)](https://github.com/sidsidoso/autenticacao-jwt-express/actions/workflows/ci.yml)
![Node.js](https://img.shields.io/badge/node-%3E%3D20.12-339933?logo=node.js&logoColor=white)
![Express](https://img.shields.io/badge/express-5.x-000000?logo=express&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-HS256-000000?logo=jsonwebtokens&logoColor=white)
[![Licença: MIT](https://img.shields.io/badge/licen%C3%A7a-MIT-yellow.svg)](LICENSE)

Sistema de autenticação e autorização desenvolvido como trabalho da disciplina de **Segurança da Informação / Desenvolvimento Web**. Implementa cadastro e login com senhas protegidas por **scrypt + salt** (módulo nativo `node:crypto`, sem bcrypt), **access token** JWT de curta duração, **refresh token** com **rotação** e **revogação** persistidas no SQLite, detecção de reuso de token, middleware de autenticação e controle de acesso por **papéis** (`admin` / `usuario`).

## Sumário

- [Tecnologias](#tecnologias)
- [Arquitetura](#arquitetura)
- [Fluxo dos tokens](#fluxo-dos-tokens)
- [Modelo de dados](#modelo-de-dados)
- [Endpoints](#endpoints)
- [Exemplos de uso](#exemplos-de-uso)
- [Decisões de implementação e segurança](#decisões-de-implementação-e-segurança)
- [Como executar](#como-executar)
- [Testes](#testes)
- [Estrutura de pastas](#estrutura-de-pastas)
- [Referências](#referências)

## Tecnologias

| Tecnologia | Uso |
| --- | --- |
| [Node.js](https://nodejs.org/) ≥ 20.12 | Execução, `crypto.scrypt`, `crypto.randomBytes`, `process.loadEnvFile` |
| [Express 5](https://expressjs.com/) | Rotas e middlewares (erros assíncronos tratados nativamente) |
| [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) | Assinatura e verificação dos access tokens (HS256) |
| [better-sqlite3](https://github.com/WiseLibs/better-sqlite3) | Usuários e refresh tokens, com transações síncronas |
| `node:test` + `fetch` nativo | Testes de integração sem dependências extras |

## Arquitetura

```
  Cliente
     │  Authorization: Bearer <accessToken>
     ▼
┌──────────────────────────────────────────────────────────────────┐
│ Express                                                          │
│  express.json({ limit: '100kb' })                                │
│        │                                                         │
│        ├── /auth/*  ──► validarCorpo ──► scrypt / tokens ─┐      │
│        │                                                  │      │
│        └── /me, /usuarios                                 │      │
│               │                                           │      │
│               ▼                                           │      │
│        autenticar ── jwt.verify(HS256) ── 401             │      │
│               │      busca usuário por PK                 │      │
│               ▼                                           │      │
│        exigirPapel('admin') ── 403                        │      │
│               │                                           ▼      │
│               └──────────► handler ──► prepared statement        │
│                                              │                   │
│                                     ┌────────▼────────┐          │
│  tratadorErros (JSON) / 404         │  SQLite (WAL)   │          │
│                                     │ usuarios        │          │
│                                     │ refresh_tokens  │          │
│                                     └─────────────────┘          │
└──────────────────────────────────────────────────────────────────┘
```

## Fluxo dos tokens

```
login ──► accessToken (JWT, 15 min) + refreshToken R1 (opaco, 7 dias, família F)

refresh(R1) ──► R1 revogado, emite R2 (mesma família F)        ✔ rotação
refresh(R2) ──► R2 revogado, emite R3                          ✔
refresh(R1) ──► R1 já revogado = REUSO ──► revoga toda a família F (R3 inclusive)  ✖ 401
logout(R3)  ──► R3 revogado                                    ✔ 204
```

Se um refresh token for roubado e usado, o próximo uso pelo dono legítimo (ou pelo atacante) apresenta um token já revogado — a API trata isso como comprometimento e encerra a sessão inteira (recomendação da RFC 9700 / OAuth 2.0 Security BCP).

## Modelo de dados

**`usuarios`**

| Coluna | Tipo | Restrições |
| --- | --- | --- |
| `id` | INTEGER | PK |
| `nome` | TEXT | obrigatório |
| `email` | TEXT | único, `COLLATE NOCASE` |
| `senha_hash` | TEXT | `scrypt$N$r$p$salt$hash` |
| `papel` | TEXT | `admin` \| `usuario` (padrão `usuario`) |
| `criado_em` | TEXT | ISO 8601 UTC |

**`refresh_tokens`**

| Coluna | Tipo | Restrições |
| --- | --- | --- |
| `id` | INTEGER | PK |
| `usuario_id` | INTEGER | FK → `usuarios.id`, `ON DELETE CASCADE`, indexado |
| `token_hash` | TEXT | SHA-256 do token, único (o token em si nunca é salvo) |
| `familia` | TEXT | UUID da cadeia de rotações, indexado |
| `expira_em` | INTEGER | epoch (s) |
| `revogado_em` | INTEGER | epoch (s); `NULL` = ativo |
| `criado_em` | INTEGER | epoch (s) |

## Endpoints

| Método | Rota | Auth | Descrição |
| --- | --- | --- | --- |
| `GET` | `/saude` | — | Verificação de disponibilidade |
| `POST` | `/auth/cadastro` | — | Cria usuário (`nome`, `email`, `senha`) com papel `usuario` |
| `POST` | `/auth/login` | — | Retorna `accessToken` + `refreshToken` |
| `POST` | `/auth/refresh` | — | Troca o `refreshToken` por um novo par (rotação) |
| `POST` | `/auth/logout` | — | Revoga o `refreshToken` informado (`204`) |
| `POST` | `/auth/logout-todos` | Bearer | Revoga todas as sessões do usuário |
| `GET` | `/me` | Bearer | Dados do usuário autenticado |
| `GET` | `/usuarios` | Bearer + `admin` | Lista usuários |
| `PATCH` | `/usuarios/:id/papel` | Bearer + `admin` | Altera o papel (`admin`/`usuario`) |

**Códigos de resposta:** `200`/`201`/`204` sucesso · `400` dados inválidos · `401` não autenticado, credenciais erradas ou token inválido/expirado/reutilizado · `403` papel insuficiente · `404` não encontrado · `409` e-mail já cadastrado ou admin removendo o próprio papel · `413` corpo acima de 100kb.

## Exemplos de uso

> No Windows (PowerShell), use `curl.exe` e aspas duplas com as internas escapadas. Os tokens abaixo foram abreviados.

**Cadastro**

```bash
curl -X POST http://localhost:3000/auth/cadastro \
  -H "Content-Type: application/json" \
  -d '{"nome":"Ana Souza","email":"ana@exemplo.com","senha":"senha-forte-123"}'
```

`201 Created`

```json
{
  "id": 1,
  "nome": "Ana Souza",
  "email": "ana@exemplo.com",
  "papel": "usuario",
  "criadoEm": "2026-11-05T19:34:35.949Z"
}
```

Repetindo o mesmo e-mail → `409 Conflict`: `{ "erro": "E-mail já cadastrado" }`

**Login**

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"ana@exemplo.com","senha":"senha-forte-123"}'
```

```json
{
  "tipo": "Bearer",
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJwYXBlbCI6InVzdWFyaW8i...V4SXe--r_odSR7YSLC0xMSFxx6zwHWGOZH0h6wadxmY",
  "expiraEm": 900,
  "refreshToken": "CyxpHkYKB-TeugJoGp9tyL4sWh0QmZvD4wQYEOGImLw"
}
```

Payload decodificado do access token:

```json
{ "papel": "usuario", "iat": 1793907292, "exp": 1793908192, "iss": "autenticacao-jwt-express", "sub": "1", "jti": "aa15e053-0207-43ef-8615-555522906054" }
```

Senha errada ou e-mail inexistente → `401`: `{ "erro": "E-mail ou senha incorretos" }` (mesma mensagem nos dois casos).

**Rota protegida `/me`**

```bash
curl http://localhost:3000/me -H "Authorization: Bearer $ACCESS_TOKEN"
```

```json
{
  "id": 1,
  "nome": "Ana Souza",
  "email": "ana@exemplo.com",
  "papel": "usuario",
  "criadoEm": "2026-11-05T19:34:35.949Z"
}
```

Sem o cabeçalho → `401` + `WWW-Authenticate: Bearer`: `{ "erro": "Token de acesso ausente" }`

**Renovação (rotação)**

```bash
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"CyxpHkYKB-TeugJoGp9tyL4sWh0QmZvD4wQYEOGImLw"}'
```

```json
{
  "tipo": "Bearer",
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiraEm": 900,
  "refreshToken": "Ig5JmMWhQgw4iuvCGhenJPsz-2ssKHqDmm3Fqqnk3Cw"
}
```

Reenviando o refresh token **antigo** → `401`:

```json
{ "erro": "Refresh token reutilizado: sessão revogada por segurança" }
```

**Autorização por papel**

```bash
curl http://localhost:3000/usuarios -H "Authorization: Bearer $ACCESS_TOKEN"
```

Como `usuario` → `403`: `{ "erro": "Acesso negado: permissão insuficiente" }`

Como `admin` → `200`:

```json
[
  {
    "id": 1,
    "nome": "Ana Souza",
    "email": "ana@exemplo.com",
    "papel": "admin",
    "criadoEm": "2026-11-05T19:34:35.949Z"
  }
]
```

**Criando o primeiro administrador**

Por segurança, nenhum endpoint público concede o papel `admin`. O primeiro administrador é promovido pela linha de comando:

```bash
npm run promover-admin -- ana@exemplo.com
# ana@exemplo.com agora é administrador.
```

## Decisões de implementação e segurança

**Senhas**

- `crypto.scrypt` (função de derivação *memory-hard*) com salt aleatório de 16 bytes por usuário e parâmetros `N=2^15, r=8, p=1`, chave de 64 bytes. Os parâmetros ficam gravados no hash (`scrypt$32768$8$1$salt$hash`), permitindo aumentar o custo no futuro sem invalidar senhas antigas.
- Comparação com `crypto.timingSafeEqual` (tempo constante).
- Versão assíncrona do scrypt: o cálculo roda no *thread pool* do libuv e não bloqueia o event loop.
- Senhas normalizadas em Unicode NFKC antes do hash (o mesmo texto digitado em teclados diferentes gera o mesmo hash).
- Login com e-mail inexistente também executa o scrypt (com um hash fictício) e devolve a mesma mensagem — evita enumeração de usuários por tempo de resposta ou por texto.

**Tokens**

- **Access token** JWT HS256 com 15 minutos de validade, `sub`, `iss`, `jti` e `papel`. Na verificação, o algoritmo é **fixado** em `HS256` (`algorithms: ['HS256']`) e o emissor é conferido — tokens `alg: none`, HS512 ou assinados com outro segredo são recusados (há testes para cada caso).
- **Refresh token** opaco (256 bits aleatórios, não é JWT). Apenas o **hash SHA-256** é armazenado: um vazamento do banco não entrega tokens utilizáveis.
- **Rotação** em uma única `db.transaction`: o token usado é revogado e o novo é emitido atomicamente. **Reuso** de token revogado revoga a família inteira.
- Logout individual (`/auth/logout`) e global (`/auth/logout-todos`). Tokens expirados do usuário são removidos a cada login.
- O middleware `autenticar` recarrega o usuário pela chave primária: exclusão de conta ou rebaixamento de papel têm efeito **imediato**, sem esperar o access token expirar.

**API**

- Segredo JWT apenas por variável de ambiente. Em `NODE_ENV=production` a aplicação **não inicia** sem `JWT_SECRET`, com segredo menor que 32 caracteres ou com o valor de exemplo. Em desenvolvimento, sem segredo, gera um aleatório temporário (nunca um valor fixo no código).
- O cadastro rejeita campos desconhecidos — enviar `"papel": "admin"` resulta em `400` (proteção contra *mass assignment*).
- Prepared statements criados uma vez por router; nenhum SQL concatenado. Índices em `usuario_id` e `familia`; `token_hash` e `email` são `UNIQUE` (índice implícito).
- `express.json({ limit: '100kb' })`, `app.disable('x-powered-by')`, erros sempre em JSON e `500` sem detalhes internos.
- A unicidade do e-mail é garantida pelo banco (`UNIQUE COLLATE NOCASE`) e o erro vira `409` — sem condição de corrida entre "verificar" e "inserir".

**Trabalhos futuros:** limitação de tentativas de login (*rate limiting*), verificação de e-mail e cabeçalhos de segurança HTTP adicionais.

## Como executar

**Pré-requisitos:** Node.js 20.12 ou superior e npm.

```bash
git clone https://github.com/sidsidoso/autenticacao-jwt-express.git
cd autenticacao-jwt-express
npm install
```

**Configuração**

```bash
# Linux/macOS
cp .env.example .env
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"   # cole em JWT_SECRET
```

```powershell
# Windows (PowerShell)
Copy-Item .env.example .env
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"   # cole em JWT_SECRET
```

| Variável | Padrão | Descrição |
| --- | --- | --- |
| `NODE_ENV` | — | `production` exige `JWT_SECRET` válido |
| `PORT` | `3000` | Porta HTTP |
| `DB_PATH` | `autenticacao.db` | Arquivo do banco SQLite |
| `JWT_SECRET` | aleatório (só em dev) | Segredo HS256, mínimo 32 caracteres |
| `ACCESS_TOKEN_TTL` | `900` | Validade do access token (s) |
| `REFRESH_TOKEN_TTL` | `604800` | Validade do refresh token (s) |

**Executar**

```bash
npm start      # produção
npm run dev    # recarrega ao salvar (node --watch)
```

## Testes

```bash
npm test
```

Testes de integração com `node:test` e `fetch` nativo contra a aplicação escutando na porta `0` com banco `:memory:`. Cobrem: hash scrypt com salt, falha de configuração em produção, cadastro (duplicado, validação, *mass assignment*), login (mensagem única), tokens adulterados/`none`/HS512/expirados, rotação, detecção de reuso, logout, logout global, papéis (`403`), mudança de papel com efeito imediato e usuário excluído.

```
ℹ tests 24
ℹ pass 24
ℹ fail 0
```

## Estrutura de pastas

```
autenticacao-jwt-express/
├── .github/workflows/ci.yml     # CI: Node 20 e 22
├── src/
│   ├── app.js                   # cria o app (recebe db e config)
│   ├── server.js                # inicia o servidor HTTP
│   ├── config.js                # variáveis de ambiente e validação do segredo
│   ├── db.js                    # SQLite: pragmas e esquema
│   ├── rotas/
│   │   ├── auth.js              # cadastro, login, refresh, logout
│   │   └── usuarios.js          # /me e rotas de admin
│   ├── middlewares/
│   │   ├── autenticacao.js      # autenticar (Bearer JWT) e exigirPapel
│   │   ├── erros.js             # ErroHttp, 404 e tratador central
│   │   └── validacao.js         # validação de corpo e de :id
│   ├── servicos/
│   │   ├── senha.js             # scrypt + salt + timingSafeEqual
│   │   └── tokens.js            # JWT HS256 e refresh tokens opacos
│   └── scripts/
│       └── promover-admin.js    # CLI para criar o primeiro admin
├── tests/
│   ├── auxiliar.js
│   └── auth.test.js
├── .env.example
├── package.json
└── LICENSE
```

## Referências

- RFC 7519 — [JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- RFC 8725 — [JSON Web Token Best Current Practices](https://datatracker.ietf.org/doc/html/rfc8725)
- RFC 9700 — [Best Current Practice for OAuth 2.0 Security](https://datatracker.ietf.org/doc/html/rfc9700) (rotação de refresh tokens)
- RFC 7914 — [The scrypt Password-Based Key Derivation Function](https://datatracker.ietf.org/doc/html/rfc7914)
- OWASP — [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) e [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- Node.js — [`crypto.scrypt`](https://nodejs.org/api/crypto.html#cryptoscryptpassword-salt-keylen-options-callback)
- better-sqlite3 — [Transações](https://github.com/WiseLibs/better-sqlite3/blob/master/docs/api.md#transactionfunction---function)

## Licença

Distribuído sob a licença MIT. Veja [LICENSE](LICENSE).
