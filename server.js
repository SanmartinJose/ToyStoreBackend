require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2');

const app = express();
app.use(express.json());
app.use(cors());

// Conexión a la base de datos
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT
});

db.connect(err => {
    if (err) {
        console.error('Error conectando a la BD:', err);
    } else {
        console.log('Base de datos conectada');
    }
});

// Endpoint de Login
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
        if (err) {
            console.error('Error en la consulta:', err);
            return res.status(500).json({ message: 'Error en el servidor' });
        }

        if (results.length === 0) {
            return res.status(401).json({ message: 'Usuario o contraseñas incorrecto' });
        }

        const user = results[0];

        // Comparar la contraseña ingresada con la hasheada en la BD
        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(401).json({ message: 'Usuario o contraseña2 incorrecto' });
        }

        if (user.status !== 'active') {
            return res.status(403).json({ message: 'Usuario deshabilitado' });
        }

        res.json({ username: user.username, message: 'Login exitoso' });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
