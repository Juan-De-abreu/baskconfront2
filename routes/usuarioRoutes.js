// routes/usuarioRoutes.js
const express = require('express');
const router = express.Router();

const {
  getAllUsuarios,
  getUsuarioById,
  createUsuario,
  updateUsuario,
  deleteUsuario
} = require('../controllers/usuarioController');

// Rutas RELATIVAS (sin /usuarios)
router.get('/', getAllUsuarios);          // → /api/usuarios
router.get('/:id', getUsuarioById);       // → /api/usuarios/:id
router.post('/', createUsuario);          // → /api/usuarios
router.put('/:id', updateUsuario);        // → /api/usuarios/:id
router.delete('/:id', deleteUsuario);     // → /api/usuarios/:id

module.exports = router;
