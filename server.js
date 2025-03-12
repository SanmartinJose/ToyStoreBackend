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

// Función para obtener la contraseña original (solo para prueba)
const getOriginalPassword = async (hashedPassword, knownPasswords) => {
    for (const pass of knownPasswords) {
        if (await bcrypt.compare(pass, hashedPassword)) {
            return pass;
        }
    }
    return 'Desconocida';
};

// Endpoint de Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
        if (err) return res.status(500).json({ message: 'Error en el servidor' });

        if (results.length === 0) return res.status(401).json({ message: 'Usuario o contraseña incorrecto' });

        const user = results[0];
        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) return res.status(401).json({ message: 'Usuario o contraseña incorrecto' });

        if (user.status !== 'active') return res.status(403).json({ message: 'Usuario deshabilitado' });

        // Obtener contraseña original (solo si tenemos una lista de contraseñas conocidas)
        const knownPasswords = ['admin123*', 'user123', 'user'];
        const originalPassword = await getOriginalPassword(user.password, knownPasswords);

        res.json({ username: user.username, password: originalPassword });
    });
});

app.listen(process.env.PORT, () => {
    console.log(`Servidor corriendo en el puerto ${process.env.PORT}`);
});
