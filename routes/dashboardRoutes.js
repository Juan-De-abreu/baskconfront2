const express = require('express');
const { getDashboardResumen } = require('../controllers/dashboardController');

const router = express.Router();

// Ruta protegida: solo para administradores (puedes agregar autenticación después)
router.get('/dashboard/resumen', getDashboardResumen);

module.exports = router;