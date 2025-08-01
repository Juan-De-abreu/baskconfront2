const db = require('../config/db');

const getAllPlataformas = async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM plataformas');
    res.json(rows);
  } catch (err) {
    console.error('Error al obtener plataformas:', err);
    res.status(500).json({ error: 'Ocurrió un error al obtener las plataformas' });
  }
};

const createPlataforma = async (req, res) => {
  const { nombre, descripcion, idestatus = 1 } = req.body;

  // 1. Validar que el nombre no esté vacío
  if (!nombre || typeof nombre !== 'string' || nombre.trim() === '') {
    return res.status(400).json({
      error: 'El campo nombre es requerido y debe ser una cadena válida'
    });
  }

  const nombreLimpio = nombre.trim();

  // 2. Validar que idestatus sea 1 o 2
  if (![1, 2].includes(Number(idestatus))) {
    return res.status(400).json({
      error: 'El campo idestatus debe ser 1 (Activo) o 2 (Inactivo)'
    });
  }

  try {
    // 3. Verificar si ya existe una plataforma con ese nombre (insensible a mayúsculas y espacios)
    const [existingRows] = await db.query(
      'SELECT idplataforma FROM plataformas WHERE LOWER(TRIM(nombre)) = ?',
      [nombreLimpio.toLowerCase()]
    );

    if (existingRows.length > 0) {
      return res.status(400).json({
        error: `Ya existe una plataforma con el nombre "${nombreLimpio}"`
      });
    }

    // 4. Insertar la nueva plataforma
    const [result] = await db.query(
      'INSERT INTO plataformas (nombre, descripcion, idestatus) VALUES (?, ?, ?)',
      [nombreLimpio, descripcion || null, idestatus]
    );

    // 5. Respuesta exitosa
    res.status(201).json({
      id: result.insertId,
      nombre: nombreLimpio,
      descripcion,
      idestatus
    });
  } catch (err) {
    console.error('Error al crear plataforma:', err);
    res.status(500).json({
      error: 'Ocurrió un error interno al crear la plataforma'
    });
  }
};

const updatePlataforma = async (req, res) => {
  const { id } = req.params;
  const { nombre, descripcion, idestatus } = req.body;

  // 1. Validar que se proporcione al menos un campo
  if (!nombre && !descripcion && idestatus === undefined) {
    return res.status(400).json({
      error: 'Debe proporcionar al menos uno de los siguientes campos: nombre, descripcion, idestatus'
    });
  }

  try {
    // 2. Verificar que la plataforma exista
    const [existingPlataforma] = await db.query(
      'SELECT idplataforma, nombre FROM plataformas WHERE idplataforma = ?',
      [id]
    );

    if (existingPlataforma.length === 0) {
      return res.status(404).json({ message: 'Plataforma no encontrada' });
    }

    const queryPromises = [];

    // 3. Validar duplicado si se cambia el nombre
    if (nombre !== undefined && nombre.trim() !== '') {
      const nombreLimpio = nombre.trim();

      const [duplicateRows] = await db.query(
        'SELECT idplataforma FROM plataformas WHERE LOWER(TRIM(nombre)) = ? AND idplataforma != ?',
        [nombreLimpio.toLowerCase(), id]
      );

      if (duplicateRows.length > 0) {
        return res.status(400).json({
          error: `Ya existe una plataforma con el nombre "${nombreLimpio}"`
        });
      }

      queryPromises.push({
        field: 'nombre = ?',
        value: nombreLimpio
      });
    }

    // 4. Agregar otros campos si están presentes
    if (descripcion !== undefined) {
      queryPromises.push({
        field: 'descripcion = ?',
        value: descripcion || null
      });
    }

    if (idestatus !== undefined) {
      if (typeof idestatus !== 'number' || ![1, 2].includes(idestatus)) {
        return res.status(400).json({ error: 'idestatus debe ser 1 (Activo) o 2 (Inactivo)' });
      }
      queryPromises.push({
        field: 'idestatus = ?',
        value: idestatus
      });
    }

    // 5. Evitar actualización vacía
    if (queryPromises.length === 0) {
      return res.status(400).json({
        error: 'No hay datos válidos para actualizar'
      });
    }

    // 6. Construir y ejecutar la consulta
    const fields = queryPromises.map(p => p.field);
    const values = queryPromises.map(p => p.value);
    values.push(id); // WHERE idplataforma = ?

    const sql = `UPDATE plataformas SET ${fields.join(', ')} WHERE idplataforma = ?`;

    const [result] = await db.query(sql, values);

    if (result.affectedRows === 0) {
      return res.status(500).json({ error: 'No se pudo actualizar la plataforma' });
    }

    // 7. Responder con los campos actualizados
    const updatedFields = {};
    if (nombre !== undefined) updatedFields.nombre = nombre.trim();
    if (descripcion !== undefined) updatedFields.descripcion = descripcion;
    if (idestatus !== undefined) updatedFields.idestatus = idestatus;

    res.json(updatedFields);
  } catch (err) {
    console.error('Error al actualizar plataforma:', err);
    res.status(500).json({
      error: 'Ocurrió un error interno al actualizar la plataforma'
    });
  }
};

const deletePlataforma = async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await db.query('DELETE FROM plataformas WHERE idplataforma = ?', [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Plataforma no encontrada' });
    }

    res.status(204).send(); // No content
  } catch (err) {
    console.error('Error al eliminar plataforma:', err);
    res.status(500).json({ error: 'No se pudo eliminar la plataforma' });
  }
};

const getPlataformaById = async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await db.query('SELECT * FROM plataformas WHERE idplataforma = ?', [id]);
    if (rows.length === 0) {
      return res.status(404).json({ message: 'Plataforma no encontrada' });
    }
    res.json(rows[0]);
  } catch (err) {
    console.error('Error al obtener plataforma por ID:', err);
    res.status(500).json({ error: 'Error al obtener la plataforma' });
  }
};

module.exports = {
  getAllPlataformas,
  getPlataformaById,
  createPlataforma,
  updatePlataforma,
  deletePlataforma
};