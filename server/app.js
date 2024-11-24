import { promisify } from 'util';
import { fileURLToPath } from 'url';
import path from 'path';
import express from 'express';
import session from 'express-session';
import Ulid from 'ulid';
import accountRoutes from './routes/accountRoutes.js';
import db from './db.js';

// replicates old node behaviour for convenience
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

app.use(
    session({
        secret: Ulid.ulid(),            // Replace with a secure random key
        resave: false,             // Avoid resaving sessions if not modified
        saveUninitialized: true,   // Save uninitialized sessions
        cookie: {                  // Configure session cookies
            secure: false,         // Set to `true` if using HTTPS
            httpOnly: true,        // Prevent client-side access to cookies
            maxAge: 1000 * 60 * 60 // Session expires after 1 hour
        }
    })
);
app.use((req, _res, next) => {
    req.session.saveAsync = promisify(req.session.save.bind(req.session));
    next();
});
app.use(express.static(path.join(__dirname, '../client')));
app.use(express.json());
app.use('/account', accountRoutes);

app.get('/status-dump', async (req, res) => {
    res.json({
        session: req.session,
        db: {
            users: await db.all(`SELECT * from users`),
            credentials: await db.all(`SELECT * from credentials`),
        }
    });
});

// define error handler last
app.use((err, req, res, next) => {
    console.error('Error occurred:', err);

    // Respond with a generic error message
    res.status(err.status || 500).json({
        error: {
            message: err.message || 'Internal Server Error',
        },
    });
});


const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});