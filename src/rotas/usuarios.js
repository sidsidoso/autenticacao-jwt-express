import { Router } from 'express';
import { ErroHttp } from '../middlewares/erros.js';
import { validarCorpo, validarId } from '../middlewares/validacao.js';
import { autenticar, exigirPapel } from '../middlewares/autenticacao.js';

export const PAPEIS = ['admin', 'usuario'];
const COLUNAS = 'id, nome, email, papel, criado_em AS criadoEm';

/** Rotas protegidas: /me para qualquer usuário autenticado, /usuarios só para admin. */
export function criarRotasUsuarios(db, config) {
  const sql = {
    buscar: db.prepare(`SELECT ${COLUNAS} FROM usuarios WHERE id = ?`),
    listar: db.prepare(`SELECT ${COLUNAS} FROM usuarios ORDER BY id`),
    alterarPapel: db.prepare(`UPDATE usuarios SET papel = ? WHERE id = ? RETURNING ${COLUNAS}`),
  };

  const router = Router();
  // Autenticação aplicada rota a rota (e não com router.use) para que caminhos
  // inexistentes continuem respondendo 404, e não 401.
  const autenticado = autenticar(db, config);

  router.get('/me', autenticado, (req, res) => {
    res.json(sql.buscar.get(req.usuario.id));
  });

  router.get('/usuarios', autenticado, exigirPapel('admin'), (req, res) => {
    res.json(sql.listar.all());
  });

  router.patch(
    '/usuarios/:id/papel',
    autenticado,
    exigirPapel('admin'),
    validarId,
    validarCorpo({ papel: { tipo: 'texto', obrigatorio: true, valores: PAPEIS } }),
    (req, res) => {
      if (req.id === req.usuario.id && req.dados.papel !== 'admin') {
        throw new ErroHttp(409, 'Um administrador não pode remover o próprio papel de admin');
      }
      const usuario = sql.alterarPapel.get(req.dados.papel, req.id);
      if (!usuario) throw new ErroHttp(404, 'Usuário não encontrado');
      res.json(usuario);
    },
  );

  return router;
}
