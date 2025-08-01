// routes/plataformaRoutes.js
const express = require('express');
const router = express.Router();

const {
    getAllPlataformas,
    getPlataformaById,
    createPlataforma,
    updatePlataforma,
    deletePlataforma
} = require('../controllers/plataformaController');

router.get('/', getAllPlataformas);           // → /api/plataformas
router.get('/:id', getPlataformaById);        // → /api/plataformas/:id
router.post('/', createPlataforma);           // → /api/plataformas
router.put('/:id', updatePlataforma);         // → /api/plataformas/:id
router.delete('/:id', deletePlataforma);      // → /api/plataformas/:id

module.exports = router;