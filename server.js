require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise'); // Usamos mysql2 con promesas
const { OAuth2Client } = require('google-auth-library');

const app = express();
app.use(express.json());
app.use(cors());

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

// Configurar el pool de conexiones
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT
});

// Endpoint de Login con usuario y contraseña
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const [results] = await db.query('SELECT * FROM users WHERE username = ?', [username]);

        if (results.length === 0 || results[0].password !== password) {
            return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
        }

        if (results[0].status !== 'active') {
            return res.status(403).json({ message: 'Usuario deshabilitado' });
        }

        res.json({ username: results[0].username, message: 'Login exitoso' });

    } catch (err) {
        console.error('Error en la consulta:', err);
        return res.status(500).json({ message: 'Error en el servidor' });
    }
});

// Endpoint de Login con Google
app.post('/google-login', async (req, res) => {
    const { token } = req.body;

    try {
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: GOOGLE_CLIENT_ID,
        });

        const payload = ticket.getPayload();
        const { email, name, picture } = payload;

        // Verificar si el usuario ya existe en la base de datos
        const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

        if (users.length === 0) {
            // Si el usuario no existe, lo insertamos
            await db.query('INSERT INTO users (username, email, password, status) VALUES (?, ?, ?, ?)', 
                [name, email, 'google_auth', 'active']);
        }

        res.json({
            message: 'Login exitoso',
            user: { email, name, picture },
        });

    } catch (error) {
        console.error('Error al verificar el token de Google:', error);
        res.status(401).json({ message: 'Autenticación fallida' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
