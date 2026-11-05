/** Erro com status HTTP, convertido em JSON pelo tratador central. */
export class ErroHttp extends Error {
  constructor(status, mensagem, detalhes) {
    super(mensagem);
    this.status = status;
    this.detalhes = detalhes;
  }
}

/** Rota não encontrada (404). */
export function naoEncontrado(req, res, next) {
  next(new ErroHttp(404, `Rota não encontrada: ${req.method} ${req.path}`));
}

/** Tratador central: toda resposta de erro sai no mesmo formato JSON. */
// eslint-disable-next-line no-unused-vars
export function tratadorErros(err, req, res, next) {
  let status = err.status ?? 500;
  let mensagem = err.message;

  if (err.type === 'entity.parse.failed') {
    status = 400;
    mensagem = 'JSON malformado no corpo da requisição';
  } else if (err.type === 'entity.too.large') {
    status = 413;
    mensagem = 'Corpo da requisição excede o limite de 100kb';
  } else if (!(err instanceof ErroHttp) && !(err.expose && status < 500)) {
    // Erro inesperado: registra no servidor e não vaza detalhes ao cliente.
    console.error(err);
    status = 500;
    mensagem = 'Erro interno do servidor';
  }

  const corpo = { erro: mensagem };
  if (err.detalhes) corpo.detalhes = err.detalhes;
  res.status(status).json(corpo);
}
