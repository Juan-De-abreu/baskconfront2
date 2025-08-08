// Importamos los módulos necesarios
const express = require('express');
const cors = require('cors');





const db = require('./config/db');

// Importamos las rutas
const juegoRoutes = require('./routes/juegoRoutes');
const generoRoutes = require('./routes/generoRoutes');
const plataformaRoutes = require('./routes/plataformaRoutes');
const dashboardRoutes = require('./routes/dashboardRoutes');
const usuarioRoutes = require('./routes/usuarioRoutes');

// Inicializamos la aplicación Express
const app = express();
const PORT = process.env.PORT || 3002;

// Middlewares - ¡ORDEN IMPORTANTE!
app.use(cors());


// Middleware más explícito para JSON
app.use(express.json({ 
  limit: '10mb',
  type: 'application/json'
}));

// Middleware para URL encoded (por si acaso)
app.use(express.urlencoded({ extended: true }));

// Servir imágenes de juegos (y otros archivos subidos)
app.use('/uploads', express.static('uploads')); // ← Nueva línea para servir las imágenes

// Middleware de debug
app.use((req, res, next) => {
 // console.log('=== REQUEST DEBUG ===');
 // console.log('Method:', req.method);
 // console.log('Path:', req.path);
 // console.log('Content-Type:', req.get('content-type'));
 // console.log('Body:', req.body);
  next();
});


// Ruta de prueba
app.get('/', (req, res) => {
  const fs = require('fs');
  const path = require('path');

  const filePath = path.join(__dirname, 'views', 'home.html');

  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(500).send('Error al cargar la página de inicio.');
    }

    // Reemplazar {{PORT}} por el puerto real
    const html = data.replace(/{{PORT}}/g, PORT);

    res.send(html);
  });
});

// Usar las rutas
app.use('/api/juegos', juegoRoutes);
app.use('/api/generos', generoRoutes);
app.use('/api/plataformas', plataformaRoutes);
app.use('/api', dashboardRoutes); // → /api/dashboard/resumen
app.use('/api/usuarios', usuarioRoutes);


// Prueba de conexión a la base de datos
db.getConnection()
  .then(conn => {
    console.log('Conexión a MySQL exitosa!');
    conn.release();
  })
  .catch(err => {
    console.error('Error de conexión a MySQL:', err);
  });

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});