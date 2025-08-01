// routes/generoRoutes.js
const express = require('express');
const router = express.Router();

const {
    getAllGeneros,
    getGeneroById,
    createGenero,
    updateGenero,
    deleteGenero
} = require('../controllers/generoController');

// Rutas RELATIVAS (sin /generos)
router.get('/', getAllGeneros);           // → /api/generos
router.get('/:id', getGeneroById);        // → /api/generos/:id
router.post('/', createGenero);           // → /api/generos
router.put('/:id', updateGenero);         // → /api/generos/:id
router.delete('/:id', deleteGenero);      // → /api/generos/:id

module.exports = router;