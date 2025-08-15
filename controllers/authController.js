// controllers/authController.js
const db = require('../config/db');
const jwt = require('jsonwebtoken');
//const bcrypt = require('bcryptjs');
const bcrypt = require('bcryptjs'); // Asegúrate de tener bcrypt instalado: npm install bcrypt

const JWT_SECRET = process.env.JWT_SECRET || 'arsistema';

// controllers/authController.js
const login = async (req, res) => {
  const { correo, clave } = req.body; // ← ahora usamos clave

  if (!correo || !clave) {
    return res.status(400).json({
      success: false,
      message: 'Correo y contraseña son obligatorios',
    });
  }

  try {
    const [rows] = await db.execute('SELECT * FROM usuarios WHERE email = ? AND activo = 1', [correo]);

    if (rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'Credenciales inválidas',
      });
    }

    const usuario = rows[0];


    // 🔐 Ahora sí: validamos la contraseña
   
    const esValida = await bcrypt.compare(clave, usuario.password);
      

    if (!esValida) {
      return res.status(401).json({
        success: false,
        message: 'Credenciales inválidas',
      });
    }

    // ✅ Generar token
    const token = jwt.sign(
      { id: usuario.idusuario, email: usuario.email, rol: usuario.rol },
      process.env.JWT_SECRET || 'arsistema',
      { expiresIn: '8h' }
    );

    res.json({
      success: true,
      message: 'Inicio de sesión exitoso',
      usuario: {
        idusuario: usuario.idusuario,
        nombre: usuario.nombre,
        email: usuario.email,
        rol: usuario.rol,
      },
      token,
    });
  } catch (error) {
    console.error('🚨 Error en login:', error);
    res.status(500).json({
      success: false,
      message: 'Error del servidor',
    });
  }
};

// ✅ Exporta correctamente
module.exports = { login };