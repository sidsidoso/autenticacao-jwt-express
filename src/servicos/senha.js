import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(scrypt);

// Parâmetros do scrypt (custo de CPU/memória). Ficam gravados no próprio hash,
// então podem ser aumentados no futuro sem invalidar senhas antigas.
const PARAMETROS = { N: 2 ** 15, r: 8, p: 1 };
const TAMANHO_SALT = 16;
const TAMANHO_CHAVE = 64;
const MEMORIA_MAXIMA = 64 * 1024 * 1024; // 64 MiB (o padrão de 32 MiB não comporta N = 2^15)

/**
 * Gera o hash da senha no formato: scrypt$N$r$p$salt$hash (salt e hash em base64).
 * @param {string} senha
 */
export async function gerarHashSenha(senha) {
  const salt = randomBytes(TAMANHO_SALT);
  const { N, r, p } = PARAMETROS;
  const chave = await scryptAsync(senha.normalize('NFKC'), salt, TAMANHO_CHAVE, { N, r, p, maxmem: MEMORIA_MAXIMA });
  return ['scrypt', N, r, p, salt.toString('base64'), chave.toString('base64')].join('$');
}

/**
 * Compara a senha com o hash armazenado em tempo constante.
 * @returns {Promise<boolean>}
 */
export async function verificarSenha(senha, armazenado) {
  const partes = armazenado.split('$');
  if (partes.length !== 6 || partes[0] !== 'scrypt') return false;
  const [N, r, p] = partes.slice(1, 4).map(Number);
  const salt = Buffer.from(partes[4], 'base64');
  const esperado = Buffer.from(partes[5], 'base64');

  try {
    const chave = await scryptAsync(senha.normalize('NFKC'), salt, esperado.length, { N, r, p, maxmem: MEMORIA_MAXIMA });
    return timingSafeEqual(chave, esperado);
  } catch {
    return false; // hash corrompido ou parâmetros inválidos
  }
}

// Hash "falso" usado quando o e-mail não existe: o login leva o mesmo tempo
// em ambos os casos, evitando a descoberta de e-mails cadastrados por tempo de resposta.
let hashFicticio;
export async function obterHashFicticio() {
  hashFicticio ??= gerarHashSenha(randomBytes(16).toString('hex'));
  return hashFicticio;
}
