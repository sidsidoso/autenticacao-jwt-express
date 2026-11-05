// Promove um usuário já cadastrado a administrador.
// Uso: npm run promover-admin -- email@exemplo.com
import { abrirBanco } from '../db.js';

try {
  process.loadEnvFile();
} catch {
  // sem .env
}

const email = process.argv[2]?.trim().toLowerCase();
if (!email) {
  console.error('Uso: npm run promover-admin -- <email>');
  process.exit(1);
}

const db = abrirBanco(process.env.DB_PATH || 'autenticacao.db');
const { changes } = db.prepare("UPDATE usuarios SET papel = 'admin' WHERE email = ?").run(email);
db.close();

if (changes === 0) {
  console.error(`Nenhum usuário encontrado com o e-mail ${email}`);
  process.exit(1);
}
console.log(`${email} agora é administrador.`);
