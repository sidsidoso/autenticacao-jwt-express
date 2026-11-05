import { abrirBanco } from './db.js';
import { criarApp } from './app.js';
import { carregarConfig } from './config.js';

// Carrega o .env se existir (recurso nativo do Node, sem dependências).
try {
  process.loadEnvFile();
} catch {
  // sem .env: usa apenas as variáveis do ambiente
}

let config;
try {
  config = carregarConfig(process.env);
} catch (err) {
  console.error(`Falha ao iniciar: ${err.message}`);
  process.exit(1);
}

const porta = Number(process.env.PORT) || 3000;
const db = abrirBanco(process.env.DB_PATH || 'autenticacao.db');
const servidor = criarApp(db, config).listen(porta, () => {
  console.log(`API de autenticação ouvindo em http://localhost:${porta}`);
});

function encerrar() {
  servidor.close(() => {
    db.close();
    process.exit(0);
  });
}
process.on('SIGINT', encerrar);
process.on('SIGTERM', encerrar);
