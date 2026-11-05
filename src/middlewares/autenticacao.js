import jwt from 'jsonwebtoken';
import { ErroHttp } from './erros.js';
import { verificarAccessToken } from '../servicos/tokens.js';

/**
 * Exige um access token válido no cabeçalho Authorization: Bearer <token>.
 * O usuário é recarregado do banco (busca por PK), então exclusões e mudanças
 * de papel valem imediatamente, sem esperar o token expirar.
 */
export function autenticar(db, config) {
  const buscarUsuario = db.prepare('SELECT id, nome, email, papel FROM usuarios WHERE id = ?');

  return (req, res, next) => {
    const [esquema, token] = (req.get('authorization') ?? '').split(' ');
    res.set('WWW-Authenticate', 'Bearer');
    if (esquema !== 'Bearer' || !token) {
      return next(new ErroHttp(401, 'Token de acesso ausente'));
    }

    let payload;
    try {
      payload = verificarAccessToken(token, config);
    } catch (err) {
      const mensagem = err instanceof jwt.TokenExpiredError ? 'Token de acesso expirado' : 'Token de acesso inválido';
      return next(new ErroHttp(401, mensagem));
    }

    const usuario = buscarUsuario.get(Number(payload.sub));
    if (!usuario) return next(new ErroHttp(401, 'Usuário do token não existe mais'));

    res.removeHeader('WWW-Authenticate');
    req.usuario = usuario;
    next();
  };
}

/** Autorização por papel: responde 403 se o usuário autenticado não tiver um dos papéis. */
export function exigirPapel(...papeis) {
  return (req, res, next) => {
    if (!papeis.includes(req.usuario?.papel)) {
      return next(new ErroHttp(403, 'Acesso negado: permissão insuficiente'));
    }
    next();
  };
}
