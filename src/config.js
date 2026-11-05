import { randomBytes } from 'node:crypto';

const TAMANHO_MINIMO_SEGREDO = 32;

/**
 * Lê a configuração a partir das variáveis de ambiente.
 * Em produção, a ausência de JWT_SECRET (ou um segredo curto) impede a inicialização.
 * @param {NodeJS.ProcessEnv} env
 */
export function carregarConfig(env = process.env) {
  const producao = env.NODE_ENV === 'production';
  let segredoJwt = env.JWT_SECRET;

  if (producao && segredoJwt?.startsWith('troque')) {
    throw new Error('JWT_SECRET ainda contém o valor de exemplo do .env.example');
  }
  if (!segredoJwt || segredoJwt.length < TAMANHO_MINIMO_SEGREDO) {
    if (producao) {
      throw new Error(`JWT_SECRET ausente ou com menos de ${TAMANHO_MINIMO_SEGREDO} caracteres em produção`);
    }
    // Desenvolvimento: segredo aleatório por execução (tokens não sobrevivem a reinícios).
    console.warn('[aviso] JWT_SECRET não definido: usando segredo aleatório temporário');
    segredoJwt = randomBytes(48).toString('base64url');
  }

  return {
    segredoJwt,
    emissor: 'autenticacao-jwt-express',
    duracaoAcessoSeg: Number(env.ACCESS_TOKEN_TTL) || 15 * 60, // 15 minutos
    duracaoRenovacaoSeg: Number(env.REFRESH_TOKEN_TTL) || 7 * 24 * 60 * 60, // 7 dias
  };
}
