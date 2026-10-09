
const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const http = require("http");
const { Server } = require("socket.io");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

dotenv.config();

const db = require("./database");

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST", "PUT", "DELETE"]
    }
});

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Home route
app.get("/", (req, res) => {
    res.json({
        message: "Lost & Found Portal Backend Running"
    });
});

// Test MySQL connection
app.get("/api/test-db", (req, res) => {
    db.query("SELECT 1 AS result", (err, rows) => {
        if (err) {
            console.error("Database query failed:", err.message);
            return res.status(500).json({
                message: "Database query failed"
            });
        }

        res.json({
            message: "MySQL connection successful",
            data: rows
        });
    });
});

// Student registration
app.post("/api/register", async (req, res) => {
    try {
        const {
            name,
            roll_number,
            email,
            phone,
            branch,
            password
        } = req.body;

        if (!name || !roll_number || !email || !password) {
            return res.status(400).json({
                message: "Name, roll number, email, and password are required"
            });
        }

        const cleanName = name.trim();
        const cleanRoll = roll_number.trim();
        const cleanEmail = email.trim().toLowerCase();

        const hashedPassword = await bcrypt.hash(password, 10);

        const sql = `
            INSERT INTO users
            (name, roll_number, email, phone, branch, password, role)
            VALUES (?, ?, ?, ?, ?, ?, 'student')
        `;

        db.query(
            sql,
            [
                cleanName,
                cleanRoll,
                cleanEmail,
                phone || null,
                branch || null,
                hashedPassword
            ],
            (err, result) => {
                if (err) {
                    if (err.code === "ER_DUP_ENTRY") {
                        return res.status(409).json({
                            message: "Roll number or email already registered"
                        });
                    }

                    console.error("Registration error:", err.message);

                    return res.status(500).json({
                        message: "Registration failed"
                    });
                }

                res.status(201).json({
                    message: "Student registered successfully",
                    user: {
                        id: result.insertId,
                        name: cleanName,
                        roll_number: cleanRoll,
                        email: cleanEmail,
                        phone: phone || null,
                        branch: branch || null,
                        role: "student"
                    }
                });
            }
        );
    } catch (error) {
        console.error("Registration error:", error.message);

        res.status(500).json({
            message: "Server error during registration"
        });
    }
});

// Student login
app.post("/api/login", (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            message: "Email and password are required"
        });
    }

    const sql = `
        SELECT id, name, roll_number, email, phone, branch, password, role
        FROM users
        WHERE email = ?
    `;

    db.query(
        sql,
        [email.trim().toLowerCase()],
        async (err, results) => {
            if (err) {
                console.error("Login database error:", err.message);

                return res.status(500).json({
                    message: "Login failed due to a server error"
                });
            }

            if (results.length === 0) {
                return res.status(401).json({
                    message: "Invalid email or password"
                });
            }

            const user = results[0];

            try {
                const passwordMatch = await bcrypt.compare(
                    password,
                    user.password
                );

                if (!passwordMatch) {
                    return res.status(401).json({
                        message: "Invalid email or password"
                    });
                }

                const secret = process.env.JWT_SECRET;

                if (!secret) {
                    console.error("JWT_SECRET is missing");

                    return res.status(500).json({
                        message: "Server configuration error"
                    });
                }

                const token = jwt.sign(
                    {
                        id: user.id,
                        email: user.email,
                        role: user.role
                    },
                    secret,
                    { expiresIn: "1d" }
                );

                delete user.password;

                res.json({
                    message: "Login successful",
                    token,
                    user
                });
            } catch (error) {
                console.error("Password verification error:", error.message);

                res.status(500).json({
                    message: "Login failed due to a server error"
                });
            }
        }
    );
});

// Get registered users (admin only)
function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
            message: "Authorization token required"
        });
    }

    const token = authHeader.split(" ")[1];
    const secret = process.env.JWT_SECRET;

    if (!secret) {
        return res.status(500).json({
            message: "Server configuration error"
        });
    }

    try {
        req.user = jwt.verify(token, secret);
        next();
    } catch (error) {
        return res.status(401).json({
            message: "Invalid or expired token"
        });
    }
}

app.get("/api/users", verifyToken, (req, res) => {
    if (req.user.role !== "admin") {
        return res.status(403).json({
            message: "Admin access required"
        });
    }

    const sql = `
        SELECT id, name, roll_number, email, phone, branch, role, created_at
        FROM users
        ORDER BY created_at DESC
    `;

    db.query(sql, (err, results) => {
        if (err) {
            console.error("Fetch users error:", err.message);

            return res.status(500).json({
                message: "Could not retrieve users"
            });
        }

        res.json({
            users: results
        });
    });
});

// Socket.IO connection
io.on("connection", (socket) => {
    console.log("User connected:", socket.id);

    socket.on("disconnect", () => {
        console.log("User disconnected:", socket.id);
    });
});

// Start server
const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
    console.log("----------------------------------");
    console.log("Lost & Found Portal");
    console.log(`Server running on port ${PORT}`);
    console.log("----------------------------------");
});