require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise'); // Usamos mysql2 con promesas

const app = express();
app.use(express.json());
app.use(cors());

// Configurar el pool de conexiones
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT
});

// Endpoint de Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Realizar la consulta a la base de datos
        const [results] = await db.query('SELECT * FROM users WHERE username = ?', [username]);

        if (results.length === 0) {
            return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
        }

        const user = results[0];

        // Comparar la contraseña ingresada con la almacenada en texto plano
        if (password !== user.password) {
            return res.status(401).json({ message: 'Usuario o contraseña incorrectos' });
        }

        if (user.status !== 'active') {
            return res.status(403).json({ message: 'Usuario deshabilitado' });
        }

        // Responder con los datos del usuario
        res.json({ username: user.username, message: 'Login exitoso' });

    } catch (err) {
        console.error('Error en la consulta:', err);
        return res.status(500).json({ message: 'Error en el servidor' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
