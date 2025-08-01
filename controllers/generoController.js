const db = require('../config/db');

const getAllGeneros = async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM generos');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

const createGenero = async (req, res) => {
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
    // 3. Verificar si ya existe un género con ese nombre (sin importar mayúsculas/minúsculas)
    const [existingRows] = await db.query(
      'SELECT idgenero FROM generos WHERE LOWER(TRIM(nombre)) = ?', 
      [nombreLimpio.toLowerCase()]
    );

    if (existingRows.length > 0) {
      return res.status(400).json({ 
        error: `Ya existe un género con el nombre "${nombreLimpio}"` 
      });
    }

    // 4. Insertar el nuevo género
    const [result] = await db.query(
      'INSERT INTO generos (nombre, descripcion, idestatus) VALUES (?, ?, ?)',
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
    // Manejo de errores del servidor
    console.error('Error al crear género:', err);
    res.status(500).json({ 
      error: 'Ocurrió un error interno al crear el género' 
    });
  }
};

const updateGenero = async (req, res) => {
  const { id } = req.params;
  const { nombre, descripcion, idestatus } = req.body;

  // 1. Validar que se proporcione al menos un campo
  if (!nombre && !descripcion && idestatus === undefined) {
    return res.status(400).json({
      error: 'Debe proporcionar al menos uno de los siguientes campos: nombre, descripcion, idestatus'
    });
  }

  try {
    // 2. Verificar que el género a actualizar exista
    const [existingGenero] = await db.query(
      'SELECT idgenero, nombre FROM generos WHERE idgenero = ?',
      [id]
    );

    if (existingGenero.length === 0) {
      return res.status(404).json({ message: 'Género no encontrado' });
    }

    const currentNombre = existingGenero[0].nombre;

    let queryPromises = [];

    // 3. Si se quiere actualizar el nombre, verificar que no esté duplicado
    if (nombre !== undefined && nombre.trim() !== '') {
      const nombreLimpio = nombre.trim();

      // Verificar si ya existe otro género (diferente al actual) con este nombre
      const [duplicateRows] = await db.query(
        'SELECT idgenero FROM generos WHERE LOWER(TRIM(nombre)) = ? AND idgenero != ?',
        [nombreLimpio.toLowerCase(), id]
      );

      if (duplicateRows.length > 0) {
        return res.status(400).json({
          error: `Ya existe un género con el nombre "${nombreLimpio}"`
        });
      }

      // Si pasa la validación, agregar el campo a la actualización
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

    // 5. Si no hay campos para actualizar (solo espacios en blanco, etc.), no hacer nada
    if (queryPromises.length === 0) {
      return res.status(400).json({
        error: 'No hay datos válidos para actualizar'
      });
    }

    // 6. Construir la consulta
    const fields = queryPromises.map(p => p.field);
    const values = queryPromises.map(p => p.value);
    values.push(id); // Para la cláusula WHERE

    const sql = `UPDATE generos SET ${fields.join(', ')} WHERE idgenero = ?`;

    const [result] = await db.query(sql, values);

    // 7. Respuesta exitosa
    const updatedFields = {};
    if (nombre !== undefined) updatedFields.nombre = nombre.trim();
    if (descripcion !== undefined) updatedFields.descripcion = descripcion;
    if (idestatus !== undefined) updatedFields.idestatus = idestatus;

    res.json(updatedFields);
  } catch (err) {
    console.error('Error al actualizar género:', err);
    res.status(500).json({
      error: 'Ocurrió un error interno al actualizar el género'
    });
  }
};

const deleteGenero = async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await db.query('DELETE FROM generos WHERE idgenero = ?', [id]);
    
    // Si no se afectó ninguna fila, el género no existe
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Género no encontrado' });
    }

    // Éxito: se eliminó el género, sin contenido que devolver
    res.status(204).send(); // No content
  } catch (err) {
    // Error del servidor
    res.status(500).json({ error: err.message });
  }
};

const getGeneroById = async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await db.query('SELECT * FROM generos WHERE idgenero = ?', [id]);
    if (rows.length === 0) {
      return res.status(404).json({ message: 'Género no encontrado' });
    }
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}
module.exports = {
  getAllGeneros,
  getGeneroById, 
  createGenero,
  updateGenero,
  deleteGenero
};