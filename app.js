const express = require("express");
const session = require("express-session");
const path = require("path");
const crypto = require("crypto");
const { promisify } = require("util");
const { Pool } = require("pg");
require("dotenv").config({ path: path.join(__dirname, ".env") });

const app = express();
const port = 3000;
const scrypt = promisify(crypto.scrypt);
const databaseUrl = process.env.DATABASE_URL;
const sessionSecret = process.env.SESSION_SECRET;

if (!databaseUrl) {
    throw new Error("DATABASE_URL must be set in HTTP Requests/blogapp/.env");
}

if (!sessionSecret || sessionSecret.length < 32) {
    throw new Error("SESSION_SECRET must be set to at least 32 characters");
}

const pool = new Pool({ connectionString: databaseUrl });

pool.on("error", (error) => {
    console.error("Unexpected PostgreSQL pool error:", error);
});

const methodOverride = require('method-override');
app.use(methodOverride('_method'));

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
// The default in-memory session store is suitable for local development only.
app.use(session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
        maxAge: 8 * 60 * 60 * 1000
    }
}));
app.get("/", async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT blog_id AS id, creator_name AS name, creator_user_id AS "creatorUserId",
                    title, body AS content,
                    date_created AS "createdAt"
             FROM blogs
             ORDER BY date_created DESC, blog_id DESC`
        );
        return res.render('index', {
            notesList: result.rows,
            currentUser: req.session.user || null
        });
    } catch (error) {
        console.error('Blog post list failed:', error);
        return res.status(503).send('Unable to load blog posts. Please try again later.');
    }
});

app.get('/signup', (req, res) => {
    res.render('signup', { message: null, name: '', username: '' });
});

app.get('/login', (req, res) => {
    res.render('existinguser', {
        message: req.query.registered ? 'Your account was created. Please sign in.' : null,
        error: null,
        username: ''
    });
});

async function verifyPassword(password, storedPassword) {
    const [algorithm, saltText, hashText] = storedPassword.split('$');
    if (algorithm !== 'scrypt' || !saltText || !hashText) {
        return false;
    }

    const salt = Buffer.from(saltText, 'base64url');
    const expectedHash = Buffer.from(hashText, 'base64url');
    if (salt.length !== 16 || expectedHash.length !== 64) {
        return false;
    }

    const actualHash = await scrypt(password, salt, expectedHash.length);
    return crypto.timingSafeEqual(actualHash, expectedHash);
}

function establishSession(req, user) {
    return new Promise((resolve, reject) => {
        req.session.regenerate((error) => {
            if (error) {
                reject(error);
                return;
            }

            req.session.user = {
                id: user.id,
                user_id: user.user_id,
                name: user.name
            };
            req.session.save((saveError) => {
                if (saveError) {
                    reject(saveError);
                    return;
                }
                resolve();
            });
        });
    });
}

app.post('/signup', async (req, res) => {
    const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
    const username = typeof req.body.user_id === 'string'
        ? req.body.user_id.trim()
        : '';
    const password = typeof req.body.password === 'string' ? req.body.password : '';

    if (!name || name.length > 255) {
        return res.status(400).render('signup', {
            message: 'Enter a name of 1 to 255 characters.',
            name,
            username
        });
    }

    if (!/^[A-Za-z0-9_-]{3,32}$/.test(username)) {
        return res.status(400).render('signup', {
            message: 'User ID must be 3 to 32 characters and use only letters, numbers, underscores, or hyphens.',
            name,
            username
        });
    }

    if (password.length < 8 || password.length > 128) {
        return res.status(400).render('signup', {
            message: 'Password must be between 8 and 128 characters.',
            name,
            username
        });
    }

    try {
        const existingUser = await pool.query(
            'SELECT 1 FROM users WHERE user_id = $1',
            [username]
        );

        if (existingUser.rowCount > 0) {
            return res.status(409).render('signup', {
                message: 'That user ID is already taken. Please choose a different one.',
                name,
                username: ''
            });
        }

        const salt = crypto.randomBytes(16);
        const passwordHash = await scrypt(password, salt, 64);
        const storedPassword = `scrypt$${salt.toString('base64url')}$${passwordHash.toString('base64url')}`;

        await pool.query(
            'INSERT INTO users (user_id, password, name) VALUES ($1, $2, $3)',
            [username, storedPassword, name]
        );

        return res.redirect('/login?registered=1');
    } catch (error) {
        if (error.code === '23505') {
            return res.status(409).render('signup', {
                message: 'That user ID is already taken. Please choose a different one.',
                name,
                username: ''
            });
        }

        console.error('Signup failed:', error);
        return res.status(503).render('signup', {
            message: 'Sign up is temporarily unavailable. Please try again later.',
            name,
            username
        });
    }
});

app.post('/login', async (req, res) => {
    const username = typeof req.body.user_id === 'string'
        ? req.body.user_id.trim()
        : '';
    const password = typeof req.body.password === 'string' ? req.body.password : '';

    if (!username || !password || password.length > 128) {
        return res.status(400).render('existinguser', {
            message: null,
            error: 'Enter a valid user ID and password.',
            username
        });
    }

    try {
        const result = await pool.query(
            'SELECT id, user_id, password, name FROM users WHERE user_id = $1',
            [username]
        );
        const user = result.rows[0];

        if (!user || !(await verifyPassword(password, user.password))) {
            return res.status(401).render('existinguser', {
                message: null,
                error: 'User ID or password is incorrect.',
                username
            });
        }

        await establishSession(req, user);
        return res.redirect('/');
    } catch (error) {
        console.error('Login failed:', error);
        return res.status(503).render('existinguser', {
            message: null,
            error: 'Sign in is temporarily unavailable. Please try again later.',
            username
        });
    }
});

app.post('/logout', (req, res) => {
    req.session.destroy((error) => {
        if (error) {
            console.error('Logout failed:', error);
            return res.status(500).send('Unable to sign out. Please try again.');
        }

        res.clearCookie('connect.sid');
        return res.redirect('/login');
    });
});

app.post('/add-note', async (req, res) => {
    const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
    const title = typeof req.body.title === 'string' ? req.body.title.trim() : '';
    const content = typeof req.body.content === 'string' ? req.body.content.trim() : '';

    if (!name || !title || !content) {
        return res.status(400).send('Name, title, and content are required');
    }

    if (name.length > 255 || title.length > 255) {
        return res.status(400).send('Name and title must be 255 characters or fewer');
    }

    try {
        await pool.query(
            `INSERT INTO blogs (creator_name, creator_user_id, title, body, date_created)
             VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)`,
            [name, req.session.user?.user_id || null, title, content]
        );
        return res.redirect('/');
    } catch (error) {
        console.error('Blog post insert failed:', error);
        return res.status(503).send('Unable to save the blog post. Please try again later.');
    }
});

async function renderEditNote(req, res) {
    const noteId = req.params.id;
    if (!/^[1-9]\d*$/.test(noteId)) {
        return res.status(404).send('Note not found');
    }

    try {
        const result = await pool.query(
            `SELECT blog_id AS id, creator_name AS name, creator_user_id AS "creatorUserId",
                    title, body AS content
             FROM blogs
             WHERE blog_id = $1`,
            [noteId]
        );
        if (result.rowCount === 0) {
            return res.status(404).send('Note not found');
        }
        const note = result.rows[0];
        if (!req.session.user || note.creatorUserId !== req.session.user.user_id) {
            return res.status(404).send('Note not found');
        }
        return res.render('edit', { note });
    } catch (error) {
        console.error('Blog post load failed:', error);
        return res.status(503).send('Unable to load the blog post. Please try again later.');
    }
}

app.get('/edit-note/:id', renderEditNote);
app.get('/delete-note/:id', renderEditNote);

app.put('/update-note/:id', async (req, res) => {
    const noteId = req.params.id;
    const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
    const title = typeof req.body.title === 'string' ? req.body.title.trim() : '';
    const content = typeof req.body.content === 'string' ? req.body.content.trim() : '';

    if (!/^[1-9]\d*$/.test(noteId)) {
        return res.status(404).send('Note not found');
    }
    if (!name || !title || !content) {
        return res.status(400).send('Name, title, and content are required');
    }
    if (name.length > 255 || title.length > 255) {
        return res.status(400).send('Name and title must be 255 characters or fewer');
    }

    try {
        const result = await pool.query(
            `UPDATE blogs
             SET creator_name = $1, title = $2, body = $3
             WHERE blog_id = $4 AND creator_user_id = $5
             RETURNING blog_id`,
            [name, title, content, noteId, req.session.user?.user_id || null]
        );
        if (result.rowCount === 0) {
            return res.status(404).send('Note not found');
        }
        return res.redirect('/');
    } catch (error) {
        console.error('Blog post update failed:', error);
        return res.status(503).send('Unable to update the blog post. Please try again later.');
    }
});

app.delete('/delete-note/:id', async (req, res) => {
    const noteId = req.params.id;
    if (!/^[1-9]\d*$/.test(noteId)) {
        return res.status(404).send('Note not found');
    }

    try {
        const result = await pool.query(
            'DELETE FROM blogs WHERE blog_id = $1 AND creator_user_id = $2 RETURNING blog_id',
            [noteId, req.session.user?.user_id || null]
        );
        if (result.rowCount === 0) {
            return res.status(404).send('Note not found');
        }
        return res.redirect('/');
    } catch (error) {
        console.error('Blog post delete failed:', error);
        return res.status(503).send('Unable to delete the blog post. Please try again later.');
    }
});

function start() {
    return app.listen(port, () => {
        console.log(`Server started on port ${port}`);
    });
}

if (require.main === module) {
    start();
}

module.exports = { app, pool, start };
