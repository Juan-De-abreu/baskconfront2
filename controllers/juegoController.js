const db = require('../config/db');

const getAllJuegos = async (req, res) => {
  try {
    const [rows] = await db.query('SELECT idjuego, a.idestatus, a.idgenero, a.nombre as njuego, a.descripcion as djuego, fechapublicacion, precio, valoracion, imagen, b.nombre as ngenero, b.descripcion as dgenero FROM juegos as a INNER JOIN generos as b on a.idgenero=b.idgenero;');
    res.json(rows);
  } catch (err) {
    console.error('Error al obtener juegos:', err);
    res.status(500).json({ error: 'Ocurrió un error al obtener los juegos' });
  }
};

const createJuego = async (req, res) => {
    const { nombre, descripcion, fechapublicacion, precio, valoracion, idgenero, idestatus = 1 } = req.body;
    const imagen = req.file ? req.file.filename : null; // ✅ Usa el nombre generado por multer

    // 1. Validar que el nombre no esté vacío
    if (!nombre || typeof nombre !== 'string' || nombre.trim() === '') {
        return res.status(400).json({
            error: 'El campo nombre es requerido y debe ser una cadena válida'
        });
    }

    const nombreLimpio = nombre.trim();

    // 2. Validar idestatus
    if (![1, 2].includes(Number(idestatus))) {
        return res.status(400).json({
            error: 'El campo idestatus debe ser 1 (Activo) o 2 (Inactivo)'
        });
    }

    // 3. Validar idgenero
    if (!idgenero || !Number.isInteger(Number(idgenero)) || Number(idgenero) <= 0) {
        return res.status(400).json({
            error: 'El campo idgenero es obligatorio y debe ser un número válido'
        });
    }

    try {
        // 4. Validar duplicado
        const [existingRows] = await db.query(
            'SELECT idjuego FROM juegos WHERE LOWER(TRIM(nombre)) = ?',
            [nombreLimpio.toLowerCase()]
        );

        if (existingRows.length > 0) {
            return res.status(400).json({
                error: `Ya existe un juego con el nombre "${nombreLimpio}"`
            });
        }

        // 5. Insertar el nuevo juego
        const [result] = await db.query(
            `INSERT INTO juegos 
            (nombre, descripcion, fechapublicacion, precio, valoracion, idgenero, idestatus, imagen) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                nombreLimpio,
                descripcion || null,
                fechapublicacion || null,
                precio !== undefined ? Number(precio) : null,
                valoracion !== undefined ? Number(valoracion) : null,
                Number(idgenero),
                Number(idestatus),
                imagen || 'default-game.jpg' // ✅ Ahora `imagen` viene del archivo subido
            ]
        );

        // 6. Respuesta exitosa
        res.status(201).json({
            idjuego: result.insertId,
            nombre: nombreLimpio,
            descripcion,
            fechapublicacion,
            precio,
            valoracion,
            idgenero: Number(idgenero),
            idestatus: Number(idestatus),
            imagen: imagen || 'default-game.jpg' // ✅ Devuelve el nombre real del archivo
        });
    } catch (err) {
        console.error('Error al crear juego:', err);
        res.status(500).json({
            error: 'Ocurrió un error interno al crear el juego'
        });
    }
};

const updateJuego = async (req, res) => {
  const { id } = req.params;
  const { nombre, descripcion, fechapublicacion, precio, valoracion, idgenero, idestatus, imagen } = req.body;

  // 1. Validar que se proporcione al menos un campo
  const hasData = [nombre, descripcion, fechapublicacion, precio, valoracion, idgenero, idestatus, imagen].some(
    field => field !== undefined
  );

  if (!hasData) {
    return res.status(400).json({
      error: 'Debe proporcionar al menos un campo para actualizar'
    });
  }

  try {
    // 2. Verificar que el juego exista
    const [existingRows] = await db.query('SELECT idjuego, nombre FROM juegos WHERE idjuego = ?', [id]);
    if (existingRows.length === 0) {
      return res.status(404).json({ message: 'Juego no encontrado' });
    }

    const queryPromises = [];

    // 3. Validar duplicado si se cambia el nombre
    if (nombre !== undefined && nombre.trim() !== '') {
      const nombreLimpio = nombre.trim();

      const [duplicateRows] = await db.query(
        'SELECT idjuego FROM juegos WHERE LOWER(TRIM(nombre)) = ? AND idjuego != ?',
        [nombreLimpio.toLowerCase(), id]
      );

      if (duplicateRows.length > 0) {
        return res.status(400).json({
          error: `Ya existe un juego con el nombre "${nombreLimpio}"`
        });
      }

      queryPromises.push({ field: 'nombre = ?', value: nombreLimpio });
    }

    // 4. Agregar otros campos si están presentes
    if (descripcion !== undefined) {
      queryPromises.push({ field: 'descripcion = ?', value: descripcion || null });
    }

    if (fechapublicacion !== undefined) {
      queryPromises.push({ field: 'fechapublicacion = ?', value: fechapublicacion || null });
    }

    if (precio !== undefined) {
      queryPromises.push({ field: 'precio = ?', value: Number(precio) });
    }

    if (valoracion !== undefined) {
      const val = Number(valoracion);
      if (val < 1 || val > 10) {
        return res.status(400).json({ error: 'La valoración debe estar entre 1 y 10' });
      }
      queryPromises.push({ field: 'valoracion = ?', value: val });
    }

    if (idgenero !== undefined) {
      if (!Number.isInteger(Number(idgenero)) || Number(idgenero) <= 0) {
        return res.status(400).json({ error: 'idgenero debe ser un número válido' });
      }
      queryPromises.push({ field: 'idgenero = ?', value: Number(idgenero) });
    }

    if (idestatus !== undefined) {
      if (![1, 2].includes(Number(idestatus))) {
        return res.status(400).json({ error: 'idestatus debe ser 1 (Activo) o 2 (Inactivo)' });
      }
      queryPromises.push({ field: 'idestatus = ?', value: Number(idestatus) });
    }

    if (imagen !== undefined) {
      queryPromises.push({ field: 'imagen = ?', value: imagen || 'default-game.jpg' });
    }

    // 5. Si no hay campos para actualizar
    if (queryPromises.length === 0) {
      return res.status(400).json({ error: 'No hay datos válidos para actualizar' });
    }

    // 6. Construir y ejecutar la consulta
    const fields = queryPromises.map(p => p.field);
    const values = queryPromises.map(p => p.value);
    values.push(id); // WHERE idjuego = ?

    const sql = `UPDATE juegos SET ${fields.join(', ')} WHERE idjuego = ?`;

    const [result] = await db.query(sql, values);

    if (result.affectedRows === 0) {
      return res.status(500).json({ error: 'No se pudo actualizar el juego' });
    }

    // 7. Responder con los campos actualizados
    const updatedFields = {};
    if (nombre !== undefined) updatedFields.nombre = nombre.trim();
    if (descripcion !== undefined) updatedFields.descripcion = descripcion;
    if (fechapublicacion !== undefined) updatedFields.fechapublicacion = fechapublicacion;
    if (precio !== undefined) updatedFields.precio = Number(precio);
    if (valoracion !== undefined) updatedFields.valoracion = Number(valoracion);
    if (idgenero !== undefined) updatedFields.idgenero = Number(idgenero);
    if (idestatus !== undefined) updatedFields.idestatus = Number(idestatus);
    if (imagen !== undefined) updatedFields.imagen = imagen;

    res.json(updatedFields);
  } catch (err) {
    console.error('Error al actualizar juego:', err);
    res.status(500).json({
      error: 'Ocurrió un error interno al actualizar el juego'
    });
  }
};

const deleteJuego = async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await db.query('DELETE FROM juegos WHERE idjuego = ?', [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Juego no encontrado' });
    }

    res.status(204).send(); // No content
  } catch (err) {
    console.error('Error al eliminar juego:', err);
    res.status(500).json({ error: 'No se pudo eliminar el juego' });
  }
};

const getJuegoById = async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await db.query('SELECT * FROM juegos WHERE idjuego = ?', [id]);
    if (rows.length === 0) {
      return res.status(404).json({ message: 'Juego no encontrado' });
    }
    res.json(rows[0]);
  } catch (err) {
    console.error('Error al obtener juego por ID:', err);
    res.status(500).json({ error: 'Error al obtener el juego' });
  }
};

module.exports = {
  getAllJuegos,
  getJuegoById,
  createJuego,
  updateJuego,
  deleteJuego
};