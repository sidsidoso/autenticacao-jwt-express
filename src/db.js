import Database from 'better-sqlite3';

const ESQUEMA = `
CREATE TABLE IF NOT EXISTS usuarios (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  nome       TEXT    NOT NULL,
  email      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
  senha_hash TEXT    NOT NULL,
  papel      TEXT    NOT NULL DEFAULT 'usuario' CHECK (papel IN ('admin', 'usuario')),
  criado_em  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Refresh tokens: só o hash SHA-256 é guardado. "familia" agrupa todos os
-- tokens nascidos do mesmo login, permitindo revogar a cadeia inteira se um
-- token já usado for reapresentado (detecção de reuso).
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  usuario_id  INTEGER NOT NULL REFERENCES usuarios (id) ON DELETE CASCADE,
  token_hash  TEXT    NOT NULL UNIQUE,
  familia     TEXT    NOT NULL,
  expira_em   INTEGER NOT NULL, -- epoch em segundos
  revogado_em INTEGER,          -- NULL = ativo
  criado_em   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_refresh_usuario ON refresh_tokens (usuario_id);
CREATE INDEX IF NOT EXISTS idx_refresh_familia ON refresh_tokens (familia);
`;

/**
 * Abre (ou cria) o banco SQLite e garante o esquema.
 * @param {string} caminho arquivo do banco ou ':memory:' (testes)
 */
export function abrirBanco(caminho = ':memory:') {
  const db = new Database(caminho);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(ESQUEMA);
  return db;
}
