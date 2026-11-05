import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import jwt from 'jsonwebtoken';
import { iniciarServidor, SEGREDO_TESTE } from './auxiliar.js';
import { carregarConfig } from '../src/config.js';
import { gerarHashSenha, verificarSenha } from '../src/servicos/senha.js';

const ANA = { nome: 'Ana Souza', email: 'Ana@Exemplo.com', senha: 'senha-forte-123' };

describe('hash de senha (scrypt)', () => {
  it('gera hashes diferentes para a mesma senha (salt) e verifica corretamente', async () => {
    const h1 = await gerarHashSenha('minha senha');
    const h2 = await gerarHashSenha('minha senha');
    assert.notEqual(h1, h2);
    assert.match(h1, /^scrypt\$32768\$8\$1\$/);
    assert.equal(await verificarSenha('minha senha', h1), true);
    assert.equal(await verificarSenha('outra senha', h1), false);
    assert.equal(await verificarSenha('minha senha', 'formato-invalido'), false);
  });
});

describe('configuração', () => {
  it('falha em produção sem JWT_SECRET, com segredo curto ou com o valor de exemplo', () => {
    assert.throws(() => carregarConfig({ NODE_ENV: 'production' }), /JWT_SECRET/);
    assert.throws(() => carregarConfig({ NODE_ENV: 'production', JWT_SECRET: 'curto' }), /JWT_SECRET/);
    assert.throws(
      () => carregarConfig({ NODE_ENV: 'production', JWT_SECRET: 'troque-por-um-segredo-aleatorio-com-pelo-menos-32-caracteres' }),
      /exemplo/,
    );
    assert.equal(carregarConfig({ NODE_ENV: 'production', JWT_SECRET: SEGREDO_TESTE }).segredoJwt, SEGREDO_TESTE);
  });
});

describe('API de autenticação', () => {
  let api;
  let sessao;
  before(async () => {
    api = await iniciarServidor();
  });
  after(() => api.fechar());

  describe('cadastro', () => {
    it('cria usuário com papel "usuario" e sem expor a senha (201)', async () => {
      const { status, corpo } = await api.req('POST', '/auth/cadastro', { corpo: ANA });
      assert.equal(status, 201);
      assert.equal(corpo.email, 'ana@exemplo.com');
      assert.equal(corpo.papel, 'usuario');
      assert.equal(corpo.senha, undefined);
      assert.equal(corpo.senha_hash, undefined);
    });

    it('guarda a senha apenas como hash scrypt', () => {
      const { senha_hash } = api.db.prepare('SELECT senha_hash FROM usuarios WHERE email = ?').get('ana@exemplo.com');
      assert.ok(!senha_hash.includes(ANA.senha));
      assert.ok(senha_hash.startsWith('scrypt$'));
    });

    it('rejeita e-mail duplicado, mesmo com outra caixa (409)', async () => {
      const { status } = await api.req('POST', '/auth/cadastro', { corpo: { ...ANA, email: 'ANA@exemplo.com' } });
      assert.equal(status, 409);
    });

    it('rejeita dados inválidos e tentativa de definir o papel (400)', async () => {
      const { status, corpo } = await api.req('POST', '/auth/cadastro', {
        corpo: { nome: 'X', email: 'sem-arroba', senha: '123', papel: 'admin' },
      });
      assert.equal(status, 400);
      assert.deepEqual(corpo.detalhes.map((d) => d.campo).sort(), ['email', 'nome', 'papel', 'senha']);
    });
  });

  describe('login e /me', () => {
    it('recusa senha errada e e-mail inexistente com a mesma mensagem (401)', async () => {
      const a = await api.req('POST', '/auth/login', { corpo: { email: ANA.email, senha: 'errada-123' } });
      const b = await api.req('POST', '/auth/login', { corpo: { email: 'ninguem@exemplo.com', senha: 'qualquer-1' } });
      assert.equal(a.status, 401);
      assert.equal(b.status, 401);
      assert.equal(a.corpo.erro, b.corpo.erro);
    });

    it('emite access token HS256 curto e refresh token opaco', async () => {
      const { status, corpo } = await api.req('POST', '/auth/login', { corpo: { email: ANA.email, senha: ANA.senha } });
      assert.equal(status, 200);
      assert.equal(corpo.tipo, 'Bearer');
      assert.equal(corpo.expiraEm, 900);
      assert.match(corpo.refreshToken, /^[A-Za-z0-9_-]{43}$/);
      const { header, payload } = jwt.decode(corpo.accessToken, { complete: true });
      assert.equal(header.alg, 'HS256');
      assert.equal(payload.papel, 'usuario');
      assert.equal(payload.exp - payload.iat, 900);
      sessao = corpo;
    });

    it('/me devolve o usuário autenticado', async () => {
      const { status, corpo } = await api.req('GET', '/me', { token: sessao.accessToken });
      assert.equal(status, 200);
      assert.equal(corpo.email, 'ana@exemplo.com');
    });

    it('/me sem token responde 401 com WWW-Authenticate', async () => {
      const { status, headers } = await api.req('GET', '/me');
      assert.equal(status, 401);
      assert.equal(headers.get('www-authenticate'), 'Bearer');
    });

    it('recusa token adulterado, com "alg: none", com outro algoritmo ou expirado', async () => {
      const payload = { sub: '1', papel: 'admin', iss: api.config.emissor };
      const tokens = {
        adulterado: sessao.accessToken.slice(0, -2) + 'xx',
        semAssinatura: jwt.sign(payload, null, { algorithm: 'none' }),
        hs512: jwt.sign(payload, SEGREDO_TESTE, { algorithm: 'HS512' }),
        outroSegredo: jwt.sign(payload, 'outro-segredo-qualquer-com-32-caracteres', { algorithm: 'HS256' }),
        expirado: jwt.sign({ ...payload, exp: Math.floor(Date.now() / 1000) - 10 }, SEGREDO_TESTE, { algorithm: 'HS256' }),
      };
      for (const [nome, token] of Object.entries(tokens)) {
        const { status, corpo } = await api.req('GET', '/me', { token });
        assert.equal(status, 401, nome);
        if (nome === 'expirado') assert.match(corpo.erro, /expirado/);
      }
    });

    it('responde 404 (e não 401) para rota inexistente', async () => {
      assert.equal((await api.req('GET', '/nao-existe')).status, 404);
    });
  });

  describe('refresh token: rotação e revogação', () => {
    let tokens;
    before(async () => {
      tokens = (await api.req('POST', '/auth/login', { corpo: { email: ANA.email, senha: ANA.senha } })).corpo;
    });

    it('troca o refresh token por um novo par (rotação)', async () => {
      const { status, corpo } = await api.req('POST', '/auth/refresh', { corpo: { refreshToken: tokens.refreshToken } });
      assert.equal(status, 200);
      assert.notEqual(corpo.refreshToken, tokens.refreshToken);
      assert.equal((await api.req('GET', '/me', { token: corpo.accessToken })).status, 200);
      tokens = { antigo: tokens.refreshToken, atual: corpo.refreshToken };
    });

    it('reuso de token já rotacionado revoga a família inteira', async () => {
      const reuso = await api.req('POST', '/auth/refresh', { corpo: { refreshToken: tokens.antigo } });
      assert.equal(reuso.status, 401);
      assert.match(reuso.corpo.erro, /reutilizado/);
      // O token legítimo mais recente também deixou de valer.
      const atual = await api.req('POST', '/auth/refresh', { corpo: { refreshToken: tokens.atual } });
      assert.equal(atual.status, 401);
    });

    it('logout revoga o refresh token (204)', async () => {
      const login = (await api.req('POST', '/auth/login', { corpo: { email: ANA.email, senha: ANA.senha } })).corpo;
      assert.equal((await api.req('POST', '/auth/logout', { corpo: { refreshToken: login.refreshToken } })).status, 204);
      assert.equal((await api.req('POST', '/auth/refresh', { corpo: { refreshToken: login.refreshToken } })).status, 401);
    });

    it('logout-todos revoga todas as sessões do usuário', async () => {
      const s1 = (await api.req('POST', '/auth/login', { corpo: { email: ANA.email, senha: ANA.senha } })).corpo;
      const s2 = (await api.req('POST', '/auth/login', { corpo: { email: ANA.email, senha: ANA.senha } })).corpo;
      const { status, corpo } = await api.req('POST', '/auth/logout-todos', { token: s1.accessToken });
      assert.equal(status, 200);
      assert.ok(corpo.sessoesRevogadas >= 2);
      for (const s of [s1, s2]) {
        assert.equal((await api.req('POST', '/auth/refresh', { corpo: { refreshToken: s.refreshToken } })).status, 401);
      }
    });

    it('recusa refresh token desconhecido ou expirado', async () => {
      const desconhecido = 'a'.repeat(43);
      assert.equal((await api.req('POST', '/auth/refresh', { corpo: { refreshToken: desconhecido } })).status, 401);

      const login = (await api.req('POST', '/auth/login', { corpo: { email: ANA.email, senha: ANA.senha } })).corpo;
      api.db.prepare('UPDATE refresh_tokens SET expira_em = 0 WHERE revogado_em IS NULL').run();
      const { status, corpo } = await api.req('POST', '/auth/refresh', { corpo: { refreshToken: login.refreshToken } });
      assert.equal(status, 401);
      assert.match(corpo.erro, /expirado/);
    });

    it('valida o formato do refresh token (400)', async () => {
      assert.equal((await api.req('POST', '/auth/refresh', { corpo: { refreshToken: 'curto' } })).status, 400);
    });
  });

  describe('papéis (admin x usuario)', () => {
    let tokenAdmin;
    let tokenAna;
    let idAna;

    before(async () => {
      await api.req('POST', '/auth/cadastro', { corpo: { nome: 'Admin', email: 'admin@exemplo.com', senha: 'admin-senha-1' } });
      api.db.prepare("UPDATE usuarios SET papel = 'admin' WHERE email = 'admin@exemplo.com'").run();
      tokenAdmin = (await api.req('POST', '/auth/login', { corpo: { email: 'admin@exemplo.com', senha: 'admin-senha-1' } })).corpo.accessToken;
      tokenAna = (await api.req('POST', '/auth/login', { corpo: { email: ANA.email, senha: ANA.senha } })).corpo.accessToken;
      idAna = (await api.req('GET', '/me', { token: tokenAna })).corpo.id;
    });

    it('usuário comum recebe 403 em rota de admin', async () => {
      assert.equal((await api.req('GET', '/usuarios', { token: tokenAna })).status, 403);
    });

    it('admin lista usuários', async () => {
      const { status, corpo } = await api.req('GET', '/usuarios', { token: tokenAdmin });
      assert.equal(status, 200);
      assert.equal(corpo.length, 2);
      assert.ok(corpo.every((u) => u.senha_hash === undefined));
    });

    it('admin promove usuário e a mudança vale imediatamente (papel lido do banco)', async () => {
      const { status, corpo } = await api.req('PATCH', `/usuarios/${idAna}/papel`, { token: tokenAdmin, corpo: { papel: 'admin' } });
      assert.equal(status, 200);
      assert.equal(corpo.papel, 'admin');
      // O token antigo da Ana ainda diz "usuario", mas a autorização usa o banco.
      assert.equal((await api.req('GET', '/usuarios', { token: tokenAna })).status, 200);
    });

    it('admin não remove o próprio papel (409) e recebe 404 para usuário inexistente', async () => {
      const idAdmin = (await api.req('GET', '/me', { token: tokenAdmin })).corpo.id;
      const proprio = await api.req('PATCH', `/usuarios/${idAdmin}/papel`, { token: tokenAdmin, corpo: { papel: 'usuario' } });
      assert.equal(proprio.status, 409);
      const inexistente = await api.req('PATCH', '/usuarios/999/papel', { token: tokenAdmin, corpo: { papel: 'usuario' } });
      assert.equal(inexistente.status, 404);
    });

    it('rejeita papel inválido (400)', async () => {
      const { status } = await api.req('PATCH', `/usuarios/${idAna}/papel`, { token: tokenAdmin, corpo: { papel: 'root' } });
      assert.equal(status, 400);
    });

    it('token de usuário excluído deixa de valer (401)', async () => {
      api.db.prepare('DELETE FROM usuarios WHERE id = ?').run(idAna);
      assert.equal((await api.req('GET', '/me', { token: tokenAna })).status, 401);
    });
  });
});
