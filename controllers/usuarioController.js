const db = require('../config/db');
const bcrypt = require('bcrypt'); // Para hashear passwords

const getAllUsuarios = async (req, res) => {
  try {
    const [rows] = await db.query('SELECT idusuario, nombre, email, rol, fechacreacion, activo FROM usuarios');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

const getUsuarioById = async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await db.query(
      'SELECT idusuario, nombre, email, rol, fechacreacion, activo FROM usuarios WHERE idusuario = ?',
      [id]
    );
    if (rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

const createUsuario = async (req, res) => {
  const { nombre, email, password, rol = 'cliente', activo = 1 } = req.body;

  // Validaciones básicas
  if (!nombre || typeof nombre !== 'string' || nombre.trim() === '') {
    return res.status(400).json({ error: 'El campo nombre es requerido y debe ser una cadena válida' });
  }

  if (!email || typeof email !== 'string' || !email.includes('@')) {
    return res.status(400).json({ error: 'El campo email es requerido y debe ser un email válido' });
  }

  if (!password || typeof password !== 'string' || password.length < 6) {
    return res.status(400).json({ error: 'El campo password es requerido y debe tener al menos 6 caracteres' });
  }

  if (!['cliente', 'admin'].includes(rol)) {
    return res.status(400).json({ error: 'El campo rol debe ser "cliente" o "admin"' });
  }

  if (![0, 1].includes(Number(activo))) {
    return res.status(400).json({ error: 'El campo activo debe ser 0 o 1' });
  }

  try {
    // Verificar si email ya existe
    const [existing] = await db.query('SELECT idusuario FROM usuarios WHERE LOWER(email) = ?', [email.toLowerCase()]);
    if (existing.length > 0) {
      return res.status(400).json({ error: `Ya existe un usuario con el email "${email}"` });
    }

    // Hashear password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insertar usuario
    const [result] = await db.query(
      'INSERT INTO usuarios (nombre, email, password, rol, activo) VALUES (?, ?, ?, ?, ?)',
      [nombre.trim(), email.trim(), hashedPassword, rol, activo]
    );

    res.status(201).json({
      idusuario: result.insertId,
      nombre: nombre.trim(),
      email: email.trim(),
      rol,
      activo
    });
  } catch (err) {
    console.error('Error al crear usuario:', err);
    res.status(500).json({ error: 'Ocurrió un error interno al crear el usuario' });
  }
};

const updateUsuario = async (req, res) => {
  const { id } = req.params;
  const { nombre, email, password, rol, activo } = req.body;

  if (
    nombre === undefined &&
    email === undefined &&
    password === undefined &&
    rol === undefined &&
    activo === undefined
  ) {
    return res.status(400).json({
      error: 'Debe proporcionar al menos un campo para actualizar: nombre, email, password, rol, activo'
    });
  }

  try {
    // Verificar si usuario existe
    const [existingUsuario] = await db.query('SELECT * FROM usuarios WHERE idusuario = ?', [id]);
    if (existingUsuario.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    let updates = [];
    let values = [];

    if (nombre !== undefined) {
      if (typeof nombre !== 'string' || nombre.trim() === '') {
        return res.status(400).json({ error: 'El campo nombre debe ser una cadena válida' });
      }
      updates.push('nombre = ?');
      values.push(nombre.trim());
    }

    if (email !== undefined) {
      if (typeof email !== 'string' || !email.includes('@')) {
        return res.status(400).json({ error: 'El campo email debe ser un correo válido' });
      }
      // Verificar que no exista otro usuario con ese email
      const [emailExists] = await db.query(
        'SELECT idusuario FROM usuarios WHERE LOWER(email) = ? AND idusuario != ?',
        [email.toLowerCase(), id]
      );
      if (emailExists.length > 0) {
        return res.status(400).json({ error: `Ya existe otro usuario con el email "${email}"` });
      }
      updates.push('email = ?');
      values.push(email.trim());
    }

    if (password !== undefined) {
      if (typeof password !== 'string' || password.length < 6) {
        return res.status(400).json({ error: 'El campo password debe tener al menos 6 caracteres' });
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      updates.push('password = ?');
      values.push(hashedPassword);
    }

    if (rol !== undefined) {
      if (!['cliente', 'admin'].includes(rol)) {
        return res.status(400).json({ error: 'El campo rol debe ser "cliente" o "admin"' });
      }
      updates.push('rol = ?');
      values.push(rol);
    }

    if (activo !== undefined) {
      if (![0, 1].includes(Number(activo))) {
        return res.status(400).json({ error: 'El campo activo debe ser 0 o 1' });
      }
      updates.push('activo = ?');
      values.push(activo);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'No hay datos válidos para actualizar' });
    }

    values.push(id);
    const sql = `UPDATE usuarios SET ${updates.join(', ')} WHERE idusuario = ?`;

    await db.query(sql, values);

    // Responder con campos actualizados, omitiendo password
    const updatedFields = {};
    if (nombre !== undefined) updatedFields.nombre = nombre.trim();
    if (email !== undefined) updatedFields.email = email.trim();
    if (rol !== undefined) updatedFields.rol = rol;
    if (activo !== undefined) updatedFields.activo = activo;

    res.json(updatedFields);
  } catch (err) {
    console.error('Error al actualizar usuario:', err);
    res.status(500).json({ error: 'Ocurrió un error interno al actualizar el usuario' });
  }
};

const deleteUsuario = async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await db.query('DELETE FROM usuarios WHERE idusuario = ?', [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    res.status(204).send(); // No content
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

module.exports = {
  getAllUsuarios,
  getUsuarioById,
  createUsuario,
  updateUsuario,
  deleteUsuario,
};
