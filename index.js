const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
app.use(bodyParser.json());

// Configuración de la conexión a la base de datos
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT || 33065
});

// Conexión a la base de datos
db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        return;
    }
    console.log('Connected to MySQL');
});

// Endpoint para registrar un usuario
app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;
    if (!username || !password || !email) {
        return res.status(400).send('Todos los campos son requeridos');
    }

    try {
        // Encriptar la contraseña
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insertar usuario en la base de datos
        const sql = 'INSERT INTO users (username, password, email) VALUES (?, ?, ?)';
        db.query(sql, [username, hashedPassword, email], (err, result) => {
            if (err) {
                console.error('Error al registrar usuario:', err);
                return res.status(500).send('Error al registrar el usuario');
            }
            res.status(201).send('Usuario registrado exitosamente');
        });
    } catch (error) {
        res.status(500).send('Error al procesar la solicitud');
    }
});

// Endpoint para login de usuario
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).send('Todos los campos son requeridos');
    }

    // Buscar usuario en la base de datos
    const sql = 'SELECT * FROM users WHERE username = ?';
    db.query(sql, [username], async (err, results) => {
        if (err) {
            console.error('Error al buscar usuario:', err);
            return res.status(500).send('Error al iniciar sesión');
        }

        if (results.length === 0) {
            return res.status(400).send('Usuario no encontrado');
        }

        const user = results[0];

        // Comparar contraseñas
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(400).send('Contraseña incorrecta');
        }

        res.send('Inicio de sesión exitoso');
    });
});

// Endpoint para consultar el perfil del usuario
app.get('/profile/:id', (req, res) => {
    const userId = req.params.id;

    // Consultar perfil de usuario
    const sql = 'SELECT id, username, email, created_at FROM users WHERE id = ?';
    db.query(sql, [userId], (err, results) => {
        if (err) {
            console.error('Error al consultar perfil:', err);
            return res.status(500).send('Error al consultar el perfil');
        }

        if (results.length === 0) {
            return res.status(404).send('Usuario no encontrado');
        }

        res.json(results[0]);
    });
});

// Iniciar el servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
