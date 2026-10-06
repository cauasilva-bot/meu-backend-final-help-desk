const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: "*" } });

const JWT_SECRET = 'super-secret-key-helpdesk-rs'; // Em produção, use variável de ambiente

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Configura pasta de uploads
if (!fs.existsSync('./uploads')) fs.mkdirSync('./uploads');

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, './uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ 
    storage, 
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB max
});

// Configuração SQLite
const db = new sqlite3.Database('./database.sqlite');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT,
        is_active INTEGER DEFAULT 1
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        operator_name TEXT,
        contact_email TEXT,
        contact_phone TEXT,
        shift TEXT,
        urgency TEXT,
        title TEXT,
        description TEXT,
        status TEXT DEFAULT 'Aberto',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_id INTEGER,
        sender_name TEXT,
        message TEXT,
        file_url TEXT,
        file_type TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(ticket_id) REFERENCES tickets(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS resolutions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_id INTEGER,
        what_was_done TEXT,
        how_it_was_done TEXT,
        FOREIGN KEY(ticket_id) REFERENCES tickets(id)
    )`);

    // Criar usuário admin inicial se não existir
    db.get("SELECT id FROM users WHERE username = 'admin'", async (err, row) => {
        if (!row) {
            const hash = await bcrypt.hash('admin123', 8);
            db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ['admin', hash, 'admin']);
            console.log("-> Usuário padrão criado: admin / admin123");
        }
    });
});

// Middleware de Autenticação
const auth = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token ausente' });
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Token inválido' });
        req.user = decoded;
        next();
    });
};

const adminAuth = (req, res, next) => {
    auth(req, res, () => {
        if (req.user.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
        next();
    });
};

// ================= ROTAS DE AUTENTICAÇÃO E USUÁRIOS =================
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err || !user) return res.status(401).json({ error: 'Credenciais inválidas' });
        if (!user.is_active) return res.status(401).json({ error: 'Usuário desativado pelo administrador' });
        
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: 'Credenciais inválidas' });

        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '12h' });
        res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
    });
});

app.get('/api/users', adminAuth, (req, res) => {
    db.all("SELECT id, username, role, is_active FROM users ORDER BY id DESC", [], (err, rows) => {
        res.json(rows);
    });
});

app.post('/api/users', adminAuth, async (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Dados incompletos' });
    const hash = await bcrypt.hash(password, 8);
    db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [username, hash, role], function(err) {
        if (err) return res.status(400).json({ error: 'Login já existe' });
        res.json({ success: true, id: this.lastID });
    });
});

app.put('/api/users/:id', adminAuth, (req, res) => {
    const { username, role } = req.body;
    db.run("UPDATE users SET username = ?, role = ? WHERE id = ?", [username, role, req.params.id], err => {
        if(err) return res.status(400).json({ error: 'Login indisponível' });
        res.json({ success: true });
    });
});

app.put('/api/users/:id/password', adminAuth, async (req, res) => {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'Senha obrigatória' });
    const hash = await bcrypt.hash(password, 8);
    db.run("UPDATE users SET password = ? WHERE id = ?", [hash, req.params.id], () => res.json({ success: true }));
});

app.put('/api/users/:id/toggle', adminAuth, (req, res) => {
    db.run("UPDATE users SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE id = ?", [req.params.id], () => res.json({ success: true }));
});

// ================= ROTAS DE CHAMADOS =================
app.post('/api/tickets', auth, (req, res) => {
    const { operator_name, contact_email, contact_phone, shift, title, description, urgency } = req.body;
    db.run(`INSERT INTO tickets (operator_name, contact_email, contact_phone, shift, title, description, urgency) 
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [operator_name, contact_email, contact_phone, shift, title, description, urgency], function(err) {
            if (err) return res.status(500).json({ error: 'Erro ao abrir chamado' });
            io.emit('ticket_update');
            res.json({ success: true, id: this.lastID });
    });
});

app.get('/api/tickets', auth, (req, res) => {
    let query = "SELECT * FROM tickets ORDER BY created_at DESC";
    if (req.user.role !== 'admin') {
        // Usuário padrão vê apenas os próprios chamados (baseado no operador, ou email)
        // Como o original não conectava ID do user ao chamado, vamos listar tudo aberto na interface, 
        // mas idealmente aqui colocaríamos um filtro. No escopo mantive para retornar todos para simplificar, 
        // ou você pode filtrar pelo username.
    }
    db.all(query, [], (err, rows) => {
        res.json(rows);
    });
});

app.get('/api/tickets/:id', auth, (req, res) => {
    db.get("SELECT * FROM tickets WHERE id = ?", [req.params.id], (err, ticket) => {
        if (!ticket) return res.status(404).json({ error: 'Não encontrado' });
        db.all("SELECT * FROM messages WHERE ticket_id = ? ORDER BY created_at ASC", [req.params.id], (err, messages) => {
            db.get("SELECT * FROM resolutions WHERE ticket_id = ?", [req.params.id], (err, resolution) => {
                res.json({ ticket, messages, resolution });
            });
        });
    });
});

app.post('/api/tickets/:id/chat', auth, upload.single('file'), (req, res) => {
    const { message } = req.body;
    const file_url = req.file ? `/uploads/${req.file.filename}` : null;
    const file_type = req.file ? req.file.mimetype : null;

    db.run("INSERT INTO messages (ticket_id, sender_name, message, file_url, file_type) VALUES (?, ?, ?, ?, ?)",
        [req.params.id, req.user.username, message || null, file_url, file_type], err => {
            if (err) return res.status(500).json({ error: 'Erro no chat' });
            io.emit('chat_update', req.params.id);
            res.json({ success: true });
        });
});

app.post('/api/tickets/:id/resolve', adminAuth, (req, res) => {
    const { what_was_done, how_it_was_done } = req.body;
    db.run("INSERT INTO resolutions (ticket_id, what_was_done, how_it_was_done) VALUES (?, ?, ?)", [req.params.id, what_was_done, how_it_was_done], () => {
        db.run("UPDATE tickets SET status = 'Resolvido' WHERE id = ?", [req.params.id], () => {
            io.emit('ticket_update');
            io.emit('chat_update', req.params.id);
            res.json({ success: true });
        });
    });
});

server.listen(3000, () => {
    console.log('Backend Helpdesk rodando na porta 3000');
});