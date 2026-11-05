import { once } from 'node:events';
import { abrirBanco } from '../src/db.js';
import { criarApp } from '../src/app.js';
import { carregarConfig } from '../src/config.js';

export const SEGREDO_TESTE = 'segredo-de-teste-com-mais-de-32-caracteres!';

/** Sobe a API em uma porta livre (0) com banco em memória. */
export async function iniciarServidor(env = {}) {
  const config = carregarConfig({ JWT_SECRET: SEGREDO_TESTE, ...env });
  const db = abrirBanco(':memory:');
  const servidor = criarApp(db, config).listen(0, '127.0.0.1');
  await once(servidor, 'listening');
  const base = `http://127.0.0.1:${servidor.address().port}`;

  /** Requisição JSON; `token` vira cabeçalho Authorization: Bearer. */
  async function req(metodo, caminho, { corpo, token } = {}) {
    const headers = {};
    if (corpo !== undefined) headers['content-type'] = 'application/json';
    if (token) headers.authorization = `Bearer ${token}`;
    const resposta = await fetch(base + caminho, {
      method: metodo,
      headers,
      body: corpo === undefined ? undefined : JSON.stringify(corpo),
    });
    const texto = await resposta.text();
    return { status: resposta.status, headers: resposta.headers, corpo: texto ? JSON.parse(texto) : null };
  }

  async function fechar() {
    servidor.closeAllConnections();
    await new Promise((resolve) => servidor.close(resolve));
    db.close();
  }

  return { db, config, req, fechar };
}
