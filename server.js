const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const port = 3000;

// Conexión a la base de datos
const db = new sqlite3.Database('./mydatabase.db', (err) => {
    if (err) {
        console.error('Error al conectar a la base de datos:', err.message);
        process.exit(1);
    }
    console.log('Conectado a la base de datos SQLite.');
    // Crear la tabla de usuarios si no existe
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    `);
});

app.use(bodyParser.urlencoded({
    extended: false
}));
app.use(bodyParser.json());

// Configuración de la sesión con cookies
app.use(session({
    secret: process.env.SESSION_SECRET || 'yh1Pz0qtkMrL3yQQiDpdtVFUb5WZ77XP', // Use a strong, randomly generated secret
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',  // Solo envía la cookie por HTTPS en producción
        httpOnly: true,                         // Previene el acceso a la cookie desde JavaScript del navegador
        maxAge: 3600000,                       // Duración de la cookie en milisegundos (1 hora)
        sameSite: 'strict'                     // Protección contra ataques CSRF
    }
}));

// Sirviendo archivos estáticos
app.use(express.static(path.join(__dirname)));

// Rutas
app.get('/register', (req, res) => {
    if (req.session.loggedIn) {
        return res.redirect('/');
    }
    res.sendFile(path.join(__dirname, 'register.html'));
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/login', (req, res) => {
    if (req.session.loggedIn) {
        return res.redirect('/');
    }
    res.sendFile(path.join(__dirname, 'login.html'));

});

const saltRounds = 10;
const failedLoginAttempts = {};
const BLOCK_TIME = 10 * 60 * 1000; // 10 minutos

// Middleware para limitar intentos de inicio de sesión
app.use((req, res, next) => {
    if (req.path === '/login' && req.method === 'POST') {
        const ip = req.ip.replace(/^::ffff:/, '');
        if (failedLoginAttempts[ip] && failedLoginAttempts[ip].attempts >= 5) {
            const timeElapsed = Date.now() - failedLoginAttempts[ip].lastAttempt;
            if (timeElapsed < BLOCK_TIME) {
                return res.status(429).send('Demasiados intentos fallidos. Inténtalo de nuevo en ' + Math.ceil((BLOCK_TIME - timeElapsed) / 60000) + ' minutos.');
            } else {
                delete failedLoginAttempts[ip];
            }
        }
    }
    next();
});

app.post('/login', (req, res) => {
    const {
        username,
        password
    } = req.body;
    const trimmedUsername = username.trim();
    const trimmedPassword = password.trim();
    const ip = req.ip.replace(/^::ffff:/, '');

    if (!trimmedUsername || !trimmedPassword) {
        return res.status(400).json({
            error: 'Por favor, introduce usuario y contraseña.'
        });
    }

    db.get("SELECT * FROM users WHERE username = ?", [trimmedUsername], (err, row) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                error: 'Error de base de datos'
            });
        }

        if (row) {
            bcrypt.compare(trimmedPassword, row.password, (compareErr, result) => {
                if (compareErr) {
                    console.error(compareErr);
                    return res.status(500).json({
                        error: 'Error al comparar contraseñas'
                    });
                }
                if (result === true) {
                    req.session.loggedIn = true;
                    req.session.username = trimmedUsername;
                    delete failedLoginAttempts[ip];
                    return res.json({
                        loggedIn: true
                    });
                } else {
                    failedLoginAttempts[ip] = failedLoginAttempts[ip] || {
                        attempts: 0
                    };
                    failedLoginAttempts[ip].attempts++;
                    failedLoginAttempts[ip].lastAttempt = Date.now();
                    return res.status(401).json({
                        loggedIn: false,
                        error: 'Credenciales incorrectas'
                    });
                }
            });
        } else {
            failedLoginAttempts[ip] = failedLoginAttempts[ip] || {
                attempts: 0
            };
            failedLoginAttempts[ip].attempts++;
            failedLoginAttempts[ip].lastAttempt = Date.now();
            return res.status(401).json({
                loggedIn: false,
                error: 'Credenciales incorrectas'
            });
        }
    });
});

app.post('/register', (req, res) => {
    const {
        username,
        password,
        'confirm-password': confirmPassword
    } = req.body;
    const trimmedUsername = username.trim();
    const trimmedPassword = password.trim();
    const trimmedConfirmPassword = confirmPassword.trim();

    if (!trimmedUsername || !trimmedPassword || !trimmedConfirmPassword) {
        return res.status(400).json({
            error: 'Todos los campos son requeridos.'
        });
    }

    if (trimmedPassword !== trimmedConfirmPassword) {
        return res.status(400).json({
            error: 'Las contraseñas no coinciden'
        });
    }

    bcrypt.hash(trimmedPassword, saltRounds, (hashErr, hashedPassword) => {
        if (hashErr) {
            console.error(hashErr);
            return res.status(500).json({
                error: 'Error al cifrar la contraseña'
            });
        }
        db.run("INSERT INTO users (username, password) VALUES (?, ?)", [trimmedUsername, hashedPassword], function (err) {
            if (err) {
                console.error(err);
                if (err.errno === 19) {
                    return res.status(409).json({
                        error: 'El usuario ya existe'
                    });
                }
                return res.status(500).json({
                    error: 'Error de base de datos'
                });
            }
            res.status(201).json({
                registered: true
            });
        });
    });
});

app.get('/session', (req, res) => {
    res.json({
        loggedIn: req.session.loggedIn || false,
        username: req.session.username || null
    });
});

app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error al cerrar sesión:', err);
            return res.status(500).json({
                loggedOut: false,
                error: 'Error al cerrar sesión'
            });
        }
        res.json({
            loggedOut: true
        });
    });
});

// Middleware de protección contra Clickjacking
app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    next();
});

// Manejo de errores 404
app.use((req, res, next) => {
    res.status(404).sendFile(path.join(__dirname, '404.html'));
});

// Manejo de errores 500
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('¡Algo salió mal!');
});

app.listen(port, () => {
    console.log(`Servidor escuchando en http://localhost:${port}`);
});

// Cierre de la conexión a la base de datos al finalizar el proceso
process.on('SIGINT', () => {
    console.log('Cerrando la conexión a la base de datos...');
    db.close((err) => {
        if (err) {
            return console.error(err.message);
        }
        console.log('Conexión a la base de datos cerrada.');
        process.exit(0);
    });
});
