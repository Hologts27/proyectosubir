const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const JWT_SECRET = 'SIGMASIGMABOY482813271371231';
const JWT_EXPIRA = '7d';
// Lista negra de JWT revocados (en memoria, debe estar antes de cualquier uso)
const jwtBlacklist = new Set();

// Mapa global para tokens de usuario
const userTokens = new Map();

const app = express();
app.use(cors());
app.use(express.json());
app.use(helmet());

// Content Security Policy (CSP) robusta
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"], // Quita 'unsafe-inline' si todo tu JS es externo y seguro
      styleSrc: ["'self'", "'unsafe-inline'"], // Quita 'unsafe-inline' si todo tu CSS es externo y seguro
      imgSrc: ["'self'", 'data:', 'blob:'],
      connectSrc: ["'self'", 'https://api.themoviedb.org'], // Agrega otros orígenes si usas APIs externas
      fontSrc: ["'self'", 'https:', 'data:'],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: [],
    },
  })
);

// Configuración de la base de datos
const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: 'root',
  database: 'CATALOGO'
};

// Rate limiting: 100 requests por 15 minutos por IP
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // Limite de 100 peticiones
  message: { error: 'Demasiadas peticiones, intenta más tarde.' }
});
app.use(limiter);

// Logs HTTP a archivo y consola
const logStream = fs.createWriteStream(path.join(__dirname, 'access.log'), { flags: 'a' });
app.use(morgan('combined', { stream: logStream }));
app.use(morgan('dev'));

// Si la tabla usuarios no tiene el campo 'role', crear automáticamente al iniciar el servidor
(async () => {
  const conn = await mysql.createConnection(dbConfig);
  try {
    const [cols] = await conn.execute("SHOW COLUMNS FROM usuarios LIKE 'role'");
    if (!cols.length) {
      await conn.execute("ALTER TABLE usuarios ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'user'");
      console.log('Campo role agregado a la tabla usuarios.');
    }
  } catch (e) {
    console.error('Error verificando/agregando campo role:', e);
  } finally {
    await conn.end();
  }
})();

// --- JWT Blacklist en BD (opcional, para persistencia tras reinicio) ---
(async () => {
  const conn = await mysql.createConnection(dbConfig);
  try {
    await conn.execute(`CREATE TABLE IF NOT EXISTS jwt_blacklist (
      token VARCHAR(512) PRIMARY KEY,
      revocado TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    // Cargar tokens revocados existentes
    const [rows] = await conn.execute('SELECT token FROM jwt_blacklist');
    for (const row of rows) {
      jwtBlacklist.add(row.token);
    }
  } catch (e) {
    console.error('Error inicializando blacklist JWT:', e);
  } finally {
    await conn.end();
  }
})();

// --- USUARIOS ---
// Al registrar usuario, permite especificar rol (solo si es admin autenticado), si no, siempre 'user'
app.post('/register', authenticateToken, requireAdmin, async (req, res) => {
  const { username, email, password, role } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  try {
    const [exists] = await conn.execute('SELECT id FROM usuarios WHERE username = ? OR email = ?', [username, email]);
    if (exists.length) return res.status(409).json({ error: 'Usuario o email ya existe' });
    const hash = await bcrypt.hash(password, 10);
    await conn.execute('INSERT INTO usuarios (username, email, password, role) VALUES (?, ?, ?, ?)', [username, email, hash, role || 'user']);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Error en el registro' });
  } finally {
    await conn.end();
  }
});

// Registro público (sin token, siempre user)
app.post('/register_public', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  try {
    const [exists] = await conn.execute('SELECT id FROM usuarios WHERE username = ? OR email = ?', [username, email]);
    if (exists.length) return res.status(409).json({ error: 'Usuario o email ya existe' });
    const hash = await bcrypt.hash(password, 10);
    await conn.execute('INSERT INTO usuarios (username, email, password, role) VALUES (?, ?, ?, ?)', [username, email, hash, 'user']);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Error en el registro' });
  } finally {
    await conn.end();
  }
});

// Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  try {
    const [users] = await conn.execute('SELECT * FROM usuarios WHERE username = ?', [username]);
    if (!users.length) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    const user = users[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    const payload = { id: user.id, username: user.username, role: user.role };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRA });
    res.json({ ok: true, user: { id: user.id, username: user.username, email: user.email, role: user.role }, token });
  } catch (e) {
    res.status(500).json({ error: 'Error en el login' });
  } finally {
    await conn.end();
  }
});

// Middleware para autenticar JWT y lista negra
async function authenticateToken(req, res, next) {
  let authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'No autorizado' });
  if (authHeader.startsWith('Bearer ')) authHeader = authHeader.slice(7);
  const token = authHeader;
  // Verifica si está en la blacklist (memoria)
  if (jwtBlacklist.has(token)) return res.status(401).json({ error: 'Token revocado' });
  // Verifica si está en la blacklist (BD)
  const conn = await mysql.createConnection(dbConfig);
  const [rows] = await conn.execute('SELECT token FROM jwt_blacklist WHERE token = ?', [token]);
  if (rows.length) {
    jwtBlacklist.add(token);
    await conn.end();
    return res.status(401).json({ error: 'Token revocado' });
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    await conn.end();
    next();
  } catch (e) {
    await conn.end();
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

// --- Middleware para verificar admin ---
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Acceso solo para administradores' });
  }
  next();
}

// --- FAVORITOS SERIES ---
// Obtener favoritos
app.get('/favoritos', async (req, res) => {
  const user_id = req.query.user_id;
  if (!user_id) return res.status(400).json({ error: 'Falta el user_id' });
  const conn = await mysql.createConnection(dbConfig);
  const [rows] = await conn.execute('SELECT serie_json FROM favoritos WHERE user_id = ?', [user_id]);
  await conn.end();
  res.json(rows.map(r => JSON.parse(r.serie_json)));
});
// Agregar favorito
app.post('/favoritos', async (req, res) => {
  const { user_id, serie } = req.body;
  if (!user_id || !serie || !serie.id) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  try {
    await conn.execute(
      'INSERT INTO favoritos (user_id, serie_id, serie_json) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE serie_json = VALUES(serie_json)',
      [user_id, serie.id, JSON.stringify(serie)]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Error al guardar favorito' });
  } finally {
    await conn.end();
  }
});
// Eliminar favorito
app.delete('/favoritos', async (req, res) => {
  const { user_id, serie_id } = req.body;
  if (!user_id || !serie_id) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  await conn.execute('DELETE FROM favoritos WHERE user_id = ? AND serie_id = ?', [user_id, serie_id]);
  await conn.end();
  res.json({ ok: true });
});

// --- FAVORITOS PELICULAS (opcional) ---
app.get('/favoritos_peliculas', async (req, res) => {
  const user_id = req.query.user_id;
  if (!user_id) return res.status(400).json({ error: 'Falta el user_id' });
  const conn = await mysql.createConnection(dbConfig);
  const [rows] = await conn.execute('SELECT pelicula_json FROM favoritos_peliculas WHERE user_id = ?', [user_id]);
  await conn.end();
  res.json(rows.map(r => JSON.parse(r.pelicula_json)));
});
app.post('/favoritos_peliculas', async (req, res) => {
  const { user_id, pelicula } = req.body;
  if (!user_id || !pelicula || !pelicula.id) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  try {
    await conn.execute(
      'INSERT INTO favoritos_peliculas (user_id, pelicula_id, pelicula_json) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE pelicula_json = VALUES(pelicula_json)',
      [user_id, pelicula.id, JSON.stringify(pelicula)]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Error al guardar favorito' });
  } finally {
    await conn.end();
  }
});
app.delete('/favoritos_peliculas', async (req, res) => {
  const { user_id, pelicula_id } = req.body;
  if (!user_id || !pelicula_id) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  await conn.execute('DELETE FROM favoritos_peliculas WHERE user_id = ? AND pelicula_id = ?', [user_id, pelicula_id]);
  await conn.end();
  res.json({ ok: true });
});

// --- TODO/TAREAS ---
// Obtener tareas
app.get('/todo', async (req, res) => {
  const user_id = req.query.user_id;
  if (!user_id) return res.status(400).json({ error: 'Falta el user_id' });
  const conn = await mysql.createConnection(dbConfig);
  const [rows] = await conn.execute('SELECT * FROM todo WHERE user_id = ?', [user_id]);
  await conn.end();
  res.json(rows);
});
// Crear tarea
app.post('/todo', async (req, res) => {
  const { user_id, titulo, descripcion } = req.body;
  if (!user_id || !titulo) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  await conn.execute('INSERT INTO todo (user_id, titulo, descripcion) VALUES (?, ?, ?)', [user_id, titulo, descripcion || '']);
  await conn.end();
  res.json({ ok: true });
});
// Actualizar tarea
app.put('/todo/:id', async (req, res) => {
  const id = req.params.id;
  const { titulo, descripcion, completado } = req.body;
  const conn = await mysql.createConnection(dbConfig);
  await conn.execute('UPDATE todo SET titulo = ?, descripcion = ?, completado = ? WHERE id = ?', [titulo, descripcion, !!completado, id]);
  await conn.end();
  res.json({ ok: true });
});
// Eliminar tarea
app.delete('/todo/:id', async (req, res) => {
  const id = req.params.id;
  const conn = await mysql.createConnection(dbConfig);
  await conn.execute('DELETE FROM todo WHERE id = ?', [id]);
  await conn.end();
  res.json({ ok: true });
});

// --- Cambiar correo electrónico ---
app.post('/update_email', async (req, res) => {
  const { user_id, email } = req.body;
  if (!user_id || !email) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  try {
    await conn.execute('UPDATE usuarios SET email = ? WHERE id = ?', [email, user_id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Error al actualizar correo' });
  } finally {
    await conn.end();
  }
});

// --- Cambiar contraseña ---
app.post('/update_password', async (req, res) => {
  const { user_id, old_password, new_password } = req.body;
  if (!user_id || !old_password || !new_password) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  try {
    const [users] = await conn.execute('SELECT password FROM usuarios WHERE id = ?', [user_id]);
    if (!users.length) return res.status(404).json({ error: 'Usuario no encontrado' });
    const valid = await bcrypt.compare(old_password, users[0].password);
    if (!valid) return res.status(401).json({ error: 'La contraseña actual no es correcta' });
    const hash = await bcrypt.hash(new_password, 10);
    await conn.execute('UPDATE usuarios SET password = ? WHERE id = ?', [hash, user_id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Error al actualizar contraseña' });
  } finally {
    await conn.end();
  }
});

// --- Rutas de administración ---
// Listar usuarios (solo admin)
app.get('/admin/usuarios', authenticateToken, requireAdmin, async (req, res) => {
  const conn = await mysql.createConnection(dbConfig);
  const [rows] = await conn.execute('SELECT id, username, email, role FROM usuarios');
  await conn.end();
  res.json(rows);
});
// Cambiar rol de usuario (solo admin)
app.post('/admin/cambiar_rol', authenticateToken, requireAdmin, async (req, res) => {
  const { user_id, role } = req.body;
  if (!user_id || !role) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  await conn.execute('UPDATE usuarios SET role = ? WHERE id = ?', [role, user_id]);
  await conn.end();
  res.json({ ok: true });
});
// Eliminar usuario (solo admin)
app.post('/admin/eliminar_usuario', authenticateToken, requireAdmin, async (req, res) => {
  const { user_id } = req.body;
  if (!user_id) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  await conn.execute('DELETE FROM usuarios WHERE id = ?', [user_id]);
  await conn.end();
  res.json({ ok: true });
});
// Resetear contraseña de usuario (solo admin)
app.post('/admin/reset_password', authenticateToken, requireAdmin, async (req, res) => {
  const { user_id, new_password } = req.body;
  if (!user_id || !new_password) return res.status(400).json({ error: 'Datos incompletos' });
  const hash = await bcrypt.hash(new_password, 10);
  const conn = await mysql.createConnection(dbConfig);
  await conn.execute('UPDATE usuarios SET password = ? WHERE id = ?', [hash, user_id]);
  await conn.end();
  res.json({ ok: true });
});
// Logs de acceso (solo admin)
app.get('/admin/logs', authenticateToken, requireAdmin, (req, res) => {
  fs.readFile(path.join(__dirname, 'access.log'), 'utf8', (err, data) => {
    if (err) return res.status(500).json({ error: 'No se pudo leer el log' });
    res.type('text/plain').send(data);
  });
});
// Limpiar logs (solo admin)
app.post('/admin/limpiar_logs', authenticateToken, requireAdmin, (req, res) => {
  fs.writeFile(path.join(__dirname, 'access.log'), '', err => {
    if (err) return res.status(500).json({ error: 'No se pudo limpiar el log' });
    res.json({ ok: true });
  });
});
// Total de favoritos (dashboard)
app.get('/admin/favoritos_total', authenticateToken, requireAdmin, async (req, res) => {
  const conn = await mysql.createConnection(dbConfig);
  try {
    const [rows1] = await conn.execute('SELECT COUNT(*) as total FROM favoritos');
    const [rows2] = await conn.execute('SELECT COUNT(*) as total FROM favoritos_peliculas');
    res.json({ total: (rows1[0].total || 0) + (rows2[0].total || 0) });
  } catch (e) {
    res.status(500).json({ error: 'Error al contar favoritos' });
  } finally {
    await conn.end();
  }
});

// --- GUARDADOS SERIES ---
// Obtener guardados de series
app.get('/guardados', authenticateToken, async (req, res) => {
  const user_id = req.query.user_id;
  if (!user_id) return res.status(400).json({ error: 'Falta el user_id' });
  const conn = await mysql.createConnection(dbConfig);
  const [rows] = await conn.execute('SELECT serie_json FROM guardados WHERE user_id = ?', [user_id]);
  await conn.end();
  res.json(rows.map(r => JSON.parse(r.serie_json)));
});
// Agregar guardado de serie
app.post('/guardados', authenticateToken, async (req, res) => {
  const { user_id, serie } = req.body;
  if (!user_id || !serie || !serie.id) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  try {
    await conn.execute(
      'INSERT IGNORE INTO guardados (user_id, serie_id, serie_json) VALUES (?, ?, ?)',
      [user_id, serie.id, JSON.stringify(serie)]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Error al guardar serie' });
  } finally {
    await conn.end();
  }
});
// Eliminar guardado de serie
app.delete('/guardados', authenticateToken, async (req, res) => {
  const { user_id, serie_id } = req.body;
  if (!user_id || !serie_id) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  try {
    await conn.execute('DELETE FROM guardados WHERE user_id = ? AND serie_id = ?', [user_id, serie_id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Error al eliminar guardado' });
  } finally {
    await conn.end();
  }
});

// --- GUARDADOS PELICULAS ---
// Obtener guardados de películas
app.get('/guardados_peliculas', authenticateToken, async (req, res) => {
  const user_id = req.query.user_id;
  if (!user_id) return res.status(400).json({ error: 'Falta el user_id' });
  const conn = await mysql.createConnection(dbConfig);
  const [rows] = await conn.execute('SELECT pelicula_json FROM guardados_peliculas WHERE user_id = ?', [user_id]);
  await conn.end();
  res.json(rows.map(r => JSON.parse(r.pelicula_json)));
});
// Agregar guardado de película
app.post('/guardados_peliculas', authenticateToken, async (req, res) => {
  const { user_id, pelicula } = req.body;
  if (!user_id || !pelicula || !pelicula.id) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  try {
    await conn.execute(
      'INSERT IGNORE INTO guardados_peliculas (user_id, pelicula_id, pelicula_json) VALUES (?, ?, ?)',
      [user_id, pelicula.id, JSON.stringify(pelicula)]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Error al guardar película' });
  } finally {
    await conn.end();
  }
});
// Eliminar guardado de película
app.delete('/guardados_peliculas', authenticateToken, async (req, res) => {
  const { user_id, pelicula_id } = req.body;
  if (!user_id || !pelicula_id) return res.status(400).json({ error: 'Datos incompletos' });
  const conn = await mysql.createConnection(dbConfig);
  try {
    await conn.execute('DELETE FROM guardados_peliculas WHERE user_id = ? AND pelicula_id = ?', [user_id, pelicula_id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Error al eliminar guardado' });
  } finally {
    await conn.end();
  }
});

// Endpoint para logout (revoca el JWT)
app.post('/logout', authenticateToken, async (req, res) => {
  let authHeader = req.headers['authorization'];
  if (authHeader.startsWith('Bearer ')) authHeader = authHeader.slice(7);
  const token = authHeader;
  jwtBlacklist.add(token);
  // Guarda en BD para persistencia
  const conn = await mysql.createConnection(dbConfig);
  await conn.execute('INSERT IGNORE INTO jwt_blacklist (token) VALUES (?)', [token]);
  await conn.end();
  res.json({ ok: true });
});

// Puerto
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log('API escuchando en puerto', PORT));
