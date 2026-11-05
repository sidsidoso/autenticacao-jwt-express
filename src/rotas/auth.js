import { Router } from 'express';
import { ErroHttp } from '../middlewares/erros.js';
import { validarCorpo } from '../middlewares/validacao.js';
import { autenticar } from '../middlewares/autenticacao.js';
import { gerarHashSenha, verificarSenha, obterHashFicticio } from '../servicos/senha.js';
import { gerarAccessToken, gerarRefreshToken, hashToken, novaFamilia } from '../servicos/tokens.js';

const REGEX_EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const esquemaCadastro = {
  nome: { tipo: 'texto', obrigatorio: true, min: 2, max: 100 },
  email: { tipo: 'texto', obrigatorio: true, max: 254, padrao: REGEX_EMAIL, mensagemPadrao: 'e-mail inválido' },
  senha: { tipo: 'texto', obrigatorio: true, min: 8, max: 128, aparar: false },
};
const esquemaLogin = {
  email: { tipo: 'texto', obrigatorio: true, max: 254 },
  senha: { tipo: 'texto', obrigatorio: true, max: 128, aparar: false },
};
const esquemaRefresh = {
  refreshToken: { tipo: 'texto', obrigatorio: true, min: 43, max: 43 },
};

const agoraSeg = () => Math.floor(Date.now() / 1000);

export function criarRotasAuth(db, config) {
  const sql = {
    inserirUsuario: db.prepare(`
      INSERT INTO usuarios (nome, email, senha_hash) VALUES (?, ?, ?)
      RETURNING id, nome, email, papel, criado_em AS criadoEm`),
    buscarPorEmail: db.prepare('SELECT id, papel, senha_hash FROM usuarios WHERE email = ?'),
    inserirRefresh: db.prepare(`
      INSERT INTO refresh_tokens (usuario_id, token_hash, familia, expira_em, criado_em)
      VALUES (@usuarioId, @tokenHash, @familia, @expiraEm, @criadoEm)`),
    buscarRefresh: db.prepare(`
      SELECT r.id, r.familia, r.expira_em, r.revogado_em, u.id AS usuario_id, u.papel
      FROM refresh_tokens r JOIN usuarios u ON u.id = r.usuario_id
      WHERE r.token_hash = ?`),
    revogarRefresh: db.prepare('UPDATE refresh_tokens SET revogado_em = ? WHERE id = ? AND revogado_em IS NULL'),
    revogarPorHash: db.prepare('UPDATE refresh_tokens SET revogado_em = ? WHERE token_hash = ? AND revogado_em IS NULL'),
    revogarFamilia: db.prepare('UPDATE refresh_tokens SET revogado_em = ? WHERE familia = ? AND revogado_em IS NULL'),
    revogarDoUsuario: db.prepare('UPDATE refresh_tokens SET revogado_em = ? WHERE usuario_id = ? AND revogado_em IS NULL'),
    limparExpirados: db.prepare('DELETE FROM refresh_tokens WHERE usuario_id = ? AND expira_em < ?'),
  };

  /** Emite o par de tokens; o refresh token pertence a uma família (cadeia de rotações). */
  function emitirTokens(usuario, familia) {
    const refreshToken = gerarRefreshToken();
    const agora = agoraSeg();
    sql.inserirRefresh.run({
      usuarioId: usuario.id,
      tokenHash: hashToken(refreshToken),
      familia,
      expiraEm: agora + config.duracaoRenovacaoSeg,
      criadoEm: agora,
    });
    return {
      tipo: 'Bearer',
      accessToken: gerarAccessToken(usuario, config),
      expiraEm: config.duracaoAcessoSeg,
      refreshToken,
    };
  }

  // Rotação atômica: o token apresentado é revogado e um novo é emitido na
  // mesma transação. Se um token já revogado reaparece, assume-se roubo e a
  // família inteira é revogada (o resultado é retornado, não lançado, para
  // que a revogação seja confirmada e não desfeita pelo rollback).
  const rotacionar = db.transaction((tokenHash) => {
    const agora = agoraSeg();
    const atual = sql.buscarRefresh.get(tokenHash);
    if (!atual) return { erro: 'Refresh token inválido' };
    if (atual.revogado_em !== null) {
      sql.revogarFamilia.run(agora, atual.familia);
      return { erro: 'Refresh token reutilizado: sessão revogada por segurança' };
    }
    if (atual.expira_em <= agora) {
      sql.revogarRefresh.run(agora, atual.id);
      return { erro: 'Refresh token expirado' };
    }
    sql.revogarRefresh.run(agora, atual.id);
    return { tokens: emitirTokens({ id: atual.usuario_id, papel: atual.papel }, atual.familia) };
  });

  const router = Router();

  router.post('/cadastro', validarCorpo(esquemaCadastro), async (req, res) => {
    const { nome, senha } = req.dados;
    const email = req.dados.email.toLowerCase();
    const senhaHash = await gerarHashSenha(senha);
    try {
      // O papel nunca vem do cliente: todo cadastro nasce como "usuario".
      const usuario = sql.inserirUsuario.get(nome, email, senhaHash);
      res.status(201).json(usuario);
    } catch (err) {
      if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') throw new ErroHttp(409, 'E-mail já cadastrado');
      throw err;
    }
  });

  router.post('/login', validarCorpo(esquemaLogin), async (req, res) => {
    const usuario = sql.buscarPorEmail.get(req.dados.email.toLowerCase());
    // Sempre executa o scrypt, mesmo sem usuário, para não vazar por tempo quais e-mails existem.
    const senhaOk = await verificarSenha(req.dados.senha, usuario?.senha_hash ?? (await obterHashFicticio()));
    if (!usuario || !senhaOk) throw new ErroHttp(401, 'E-mail ou senha incorretos');

    sql.limparExpirados.run(usuario.id, agoraSeg());
    res.json(emitirTokens(usuario, novaFamilia()));
  });

  router.post('/refresh', validarCorpo(esquemaRefresh), (req, res) => {
    const resultado = rotacionar(hashToken(req.dados.refreshToken));
    if (resultado.erro) throw new ErroHttp(401, resultado.erro);
    res.json(resultado.tokens);
  });

  // Logout de uma sessão: revoga o refresh token informado (idempotente).
  router.post('/logout', validarCorpo(esquemaRefresh), (req, res) => {
    sql.revogarPorHash.run(agoraSeg(), hashToken(req.dados.refreshToken));
    res.status(204).end();
  });

  // Logout global: revoga todos os refresh tokens do usuário autenticado.
  router.post('/logout-todos', autenticar(db, config), (req, res) => {
    const { changes } = sql.revogarDoUsuario.run(agoraSeg(), req.usuario.id);
    res.json({ sessoesRevogadas: changes });
  });

  return router;
}
