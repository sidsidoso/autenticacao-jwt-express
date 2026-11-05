import { ErroHttp } from './erros.js';

/**
 * Valida um valor contra uma regra simples. Retorna a mensagem de erro ou undefined.
 * Regra: { tipo: 'texto' | 'inteiro', obrigatorio, min, max, valores, padrao, mensagemPadrao, aparar }
 */
function verificar(valor, regra) {
  if (regra.tipo === 'texto') {
    if (typeof valor !== 'string') return 'deve ser um texto';
    const v = regra.aparar === false ? valor : valor.trim();
    if (regra.min !== undefined && v.length < regra.min) return `deve ter ao menos ${regra.min} caractere(s)`;
    if (regra.max !== undefined && v.length > regra.max) return `deve ter no máximo ${regra.max} caracteres`;
    if (regra.valores && !regra.valores.includes(v)) return `deve ser um de: ${regra.valores.join(', ')}`;
    if (regra.padrao && !regra.padrao.test(v)) return regra.mensagemPadrao ?? 'formato inválido';
    return undefined;
  }
  if (regra.tipo === 'inteiro') {
    if (!Number.isInteger(valor)) return 'deve ser um número inteiro';
    if (regra.min !== undefined && valor < regra.min) return `deve ser maior ou igual a ${regra.min}`;
    if (regra.max !== undefined && valor > regra.max) return `deve ser menor ou igual a ${regra.max}`;
    return undefined;
  }
  return 'tipo de regra desconhecido';
}

/**
 * Middleware que valida req.body contra um esquema e grava os dados limpos em req.dados.
 * Campos fora do esquema são rejeitados (evita mass assignment, ex.: enviar "papel").
 */
export function validarCorpo(esquema) {
  return (req, res, next) => {
    const corpo = req.body;
    if (!corpo || typeof corpo !== 'object' || Array.isArray(corpo)) {
      return next(new ErroHttp(400, 'O corpo da requisição deve ser um objeto JSON'));
    }

    const erros = [];
    const dados = {};
    for (const campo of Object.keys(corpo)) {
      if (!Object.hasOwn(esquema, campo)) erros.push({ campo, mensagem: 'campo não permitido' });
    }
    for (const [campo, regra] of Object.entries(esquema)) {
      const valor = corpo[campo];
      if (valor === undefined) {
        if (regra.obrigatorio) erros.push({ campo, mensagem: 'campo obrigatório' });
        continue;
      }
      const mensagem = verificar(valor, regra);
      if (mensagem) erros.push({ campo, mensagem });
      else dados[campo] = typeof valor === 'string' && regra.aparar !== false ? valor.trim() : valor;
    }

    if (erros.length) return next(new ErroHttp(400, 'Dados inválidos', erros));
    req.dados = dados;
    next();
  };
}

/** Garante que :id seja um inteiro positivo. */
export function validarId(req, res, next) {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) {
    return next(new ErroHttp(400, 'O parâmetro id deve ser um inteiro positivo'));
  }
  req.id = id;
  next();
}
