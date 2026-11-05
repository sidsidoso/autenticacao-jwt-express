import { createHash, randomBytes, randomUUID } from 'node:crypto';
import jwt from 'jsonwebtoken';

const ALGORITMO = 'HS256';

/** Assina o access token (JWT curto) com o papel do usuário. */
export function gerarAccessToken(usuario, config) {
  return jwt.sign({ papel: usuario.papel }, config.segredoJwt, {
    algorithm: ALGORITMO,
    expiresIn: config.duracaoAcessoSeg,
    issuer: config.emissor,
    subject: String(usuario.id),
    jwtid: randomUUID(), // identificador único de cada token
  });
}

/**
 * Verifica o access token. O algoritmo é fixado em HS256 para impedir
 * ataques de troca de algoritmo (ex.: "alg": "none").
 * Lança JsonWebTokenError / TokenExpiredError em caso de falha.
 */
export function verificarAccessToken(token, config) {
  return jwt.verify(token, config.segredoJwt, { algorithms: [ALGORITMO], issuer: config.emissor });
}

/** Refresh token opaco: 256 bits aleatórios em base64url (não é JWT). */
export function gerarRefreshToken() {
  return randomBytes(32).toString('base64url');
}

/** Apenas o hash SHA-256 do refresh token vai para o banco. */
export function hashToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

export function novaFamilia() {
  return randomUUID();
}
