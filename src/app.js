import express from 'express';
import { criarRotasAuth } from './rotas/auth.js';
import { criarRotasUsuarios } from './rotas/usuarios.js';
import { naoEncontrado, tratadorErros } from './middlewares/erros.js';

/**
 * Cria a aplicação Express. Banco e configuração são injetados,
 * o que permite testar com banco em memória e segredo próprio.
 * @param {import('better-sqlite3').Database} db
 * @param {ReturnType<import('./config.js').carregarConfig>} config
 */
export function criarApp(db, config) {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '100kb' }));

  app.get('/saude', (req, res) => res.json({ status: 'ok' }));
  app.use('/auth', criarRotasAuth(db, config));
  app.use(criarRotasUsuarios(db, config));

  app.use(naoEncontrado);
  app.use(tratadorErros);
  return app;
}
