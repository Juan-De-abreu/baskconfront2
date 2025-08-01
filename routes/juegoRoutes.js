// routes/juegoRoutes.js
const express = require('express');
const multer = require('multer');
const { 
    getAllJuegos, 
    getJuegoById, 
    createJuego, 
    updateJuego, 
    deleteJuego 
} = require('../controllers/juegoController');

const router = express.Router();

// Configuración de multer
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/juegos/img/');
    },
    filename: (req, file, cb) => {
        const ext = file.originalname.split('.').pop();
        const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1E9)}`;
        cb(null, `juego_${uniqueSuffix}.${ext}`);
    }
});

const upload = multer({ storage });

// Rutas (relativas)
router.get('/', getAllJuegos);                    // → /api/juegos
router.get('/:id', getJuegoById);                 // → /api/juegos/:id
router.post('/', upload.single('imagen'), createJuego);     // → /api/juegos
router.put('/:id', upload.single('imagen'), updateJuego);   // → /api/juegos/:id
router.delete('/:id', deleteJuego);               // → /api/juegos/:id

module.exports = router;