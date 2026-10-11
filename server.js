
const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const http = require("http");
const { Server } = require("socket.io");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

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
app.use((error, req, res, next) => {
    if (error && error.type === "entity.parse.failed") {
        return res.status(400).json({
            message: "Request body must contain valid JSON"
        });
    }

    next(error);
});

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
        } = req.body || {};

        if (
            typeof name !== "string" ||
            typeof roll_number !== "string" ||
            typeof email !== "string" ||
            typeof password !== "string" ||
            !name.trim() ||
            !roll_number.trim() ||
            !email.trim() ||
            !password
        ) {
            return res.status(400).json({
                message: "Name, roll number, email, and password are required"
            });
        }

        const cleanName = name.trim();
        const cleanRoll = roll_number.trim();
        const cleanEmail = email.trim().toLowerCase();
        const cleanPhone = typeof phone === "string" ? phone.trim() : "";
        const cleanBranch = typeof branch === "string" ? branch.trim() : "";

        if (
            cleanName.length > 100 ||
            cleanRoll.length > 50 ||
            cleanEmail.length > 100 ||
            cleanPhone.length > 15 ||
            cleanBranch.length > 50
        ) {
            return res.status(400).json({
                message: "One or more registration fields exceed the allowed length"
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                message: "Password must be at least 8 characters long"
            });
        }

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
                cleanPhone || null,
                cleanBranch || null,
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
                        phone: cleanPhone || null,
                        branch: cleanBranch || null,
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

app.post("/api/password/forgot", (req, res) => {
    const { email } = req.body || {};
    const smtpHost = process.env.SMTP_HOST;
    const smtpUser = process.env.SMTP_USER;
    const smtpPassword = process.env.SMTP_PASSWORD;
    const frontendUrl = process.env.FRONTEND_URL;

    if (!smtpHost || !smtpUser || !smtpPassword || !frontendUrl) {
        console.error("Password reset email configuration is incomplete");
        return res.status(503).json({
            message: "Password reset email is not configured. Contact the administrator."
        });
    }

    let resetPageUrl;
    try {
        resetPageUrl = new URL(frontendUrl);
        if (!["http:", "https:"].includes(resetPageUrl.protocol)) {
            throw new Error("Unsupported frontend URL protocol");
        }
    } catch (error) {
        console.error("Invalid FRONTEND_URL configuration:", error.message);
        return res.status(500).json({
            message: "Password reset email is not configured correctly"
        });
    }

    if (typeof email !== "string" || !email.trim()) {
        return res.status(400).json({
            message: "Enter your registered email address"
        });
    }

    const cleanEmail = email.trim().toLowerCase();
    if (cleanEmail.length > 100 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
        return res.status(400).json({
            message: "Enter a valid email address"
        });
    }

    db.query(
        "SELECT id, name, email FROM users WHERE email = ? AND role = 'student' LIMIT 1",
        [cleanEmail],
        (findError, users) => {
            if (findError) {
                console.error("Find password reset user error:", findError.message);
                return res.status(500).json({
                    message: "Could not start password reset"
                });
            }

            if (users.length === 0) {
                return res.json({
                    message: "If that email belongs to a student account, a reset link will be sent."
                });
            }

            const user = users[0];
            const resetToken = crypto.randomBytes(32).toString("hex");
            const tokenHash = crypto.createHash("sha256").update(resetToken).digest("hex");
            const expiresAt = new Date(Date.now() + 60 * 60 * 1000);

            db.query(
                "DELETE FROM password_resets WHERE user_id = ?",
                [user.id],
                (deleteError) => {
                    if (deleteError) {
                        console.error("Replace password reset token error:", deleteError.message);
                        return res.status(500).json({
                            message: "Could not start password reset"
                        });
                    }

                    db.query(
                        "INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
                        [user.id, tokenHash, expiresAt],
                        (insertError) => {
                            if (insertError) {
                                console.error("Save password reset token error:", insertError.message);
                                return res.status(500).json({
                                    message: "Could not start password reset"
                                });
                            }

                            const resetUrl = new URL("/reset-password", resetPageUrl);
                            resetUrl.searchParams.set("token", resetToken);
                            const safeName = user.name.replace(/[&<>"']/g, (character) => ({
                                "&": "&amp;",
                                "<": "&lt;",
                                ">": "&gt;",
                                "\"": "&quot;",
                                "'": "&#39;"
                            })[character]);

                            const transporter = nodemailer.createTransport({
                                host: smtpHost,
                                port: Number(process.env.SMTP_PORT || 587),
                                secure: process.env.SMTP_SECURE === "true",
                                auth: {
                                    user: smtpUser,
                                    pass: smtpPassword
                                }
                            });

                            transporter.sendMail({
                                from: process.env.SMTP_FROM || smtpUser,
                                to: user.email,
                                subject: "Reset your Lost & Found Portal password",
                                text:
                                    `Hello ${user.name},\n\n` +
                                    `Use this link to reset your password. It expires in 1 hour:\n${resetUrl.toString()}\n\n` +
                                    "If you did not request this, you can ignore this email.",
                                html:
                                    `<p>Hello ${safeName},</p>` +
                                    `<p><a href="${resetUrl.toString()}">Reset your password</a></p>` +
                                    "<p>This link expires in 1 hour. If you did not request this, ignore this email.</p>"
                            }, (mailError) => {
                                if (mailError) {
                                    console.error("Send password reset email error:", mailError.message);
                                    db.query(
                                        "DELETE FROM password_resets WHERE token_hash = ?",
                                        [tokenHash],
                                        (cleanupError) => {
                                            if (cleanupError) {
                                                console.error("Remove unsent reset token error:", cleanupError.message);
                                            }
                                        }
                                    );
                                    return res.status(502).json({
                                        message: "Could not send reset email. Check the email service configuration and try again."
                                    });
                                }

                                res.json({
                                    message: "If that email belongs to a student account, a reset link will be sent."
                                });
                            });
                        }
                    );
                }
            );
        }
    );
});

app.post("/api/password/reset", async (req, res) => {
    const { token, password } = req.body || {};

    if (
        typeof token !== "string" ||
        !/^[a-f0-9]{64}$/.test(token) ||
        typeof password !== "string" ||
        password.length < 8
    ) {
        return res.status(400).json({
            message: "A valid reset link and a password of at least 8 characters are required"
        });
    }

    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    let connection;

    try {
        connection = await db.promise().getConnection();
        await connection.beginTransaction();

        const [resets] = await connection.query(
            `SELECT user_id FROM password_resets
             WHERE token_hash = ? AND expires_at > NOW()
             LIMIT 1 FOR UPDATE`,
            [tokenHash]
        );

        if (resets.length === 0) {
            await connection.rollback();
            return res.status(400).json({
                message: "This password reset link is invalid or has expired. Request a new one."
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await connection.query(
            "UPDATE users SET password = ? WHERE id = ? AND role = 'student'",
            [hashedPassword, resets[0].user_id]
        );
        await connection.query(
            "DELETE FROM password_resets WHERE token_hash = ?",
            [tokenHash]
        );
        await connection.commit();

        res.json({ message: "Password reset successfully. You can now log in." });
    } catch (error) {
        if (connection) {
            try {
                await connection.rollback();
            } catch (rollbackError) {
                console.error("Password reset rollback error:", rollbackError.message);
            }
        }
        console.error("Reset password error:", error.message);
        res.status(500).json({
            message: "Could not reset your password. Please try again."
        });
    } finally {
        if (connection) {
            connection.release();
        }
    }
});

// Student login
app.post("/api/login", (req, res) => {
    const { email, password } = req.body || {};

    if (
        typeof email !== "string" ||
        typeof password !== "string" ||
        !email.trim() ||
        !password
    ) {
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

// Admin login
app.post("/api/admin/login", (req, res) => {
    const { email, password } = req.body || {};
    const adminEmail = process.env.ADMIN_EMAIL;
    const adminPassword = process.env.ADMIN_PASSWORD;
    const secret = process.env.JWT_SECRET;

    if (!adminEmail || !adminPassword || !secret) {
        console.error("Admin login configuration is incomplete");
        return res.status(500).json({
            message: "Admin login is not configured on the server"
        });
    }

    if (typeof email !== "string" || typeof password !== "string") {
        return res.status(400).json({
            message: "Email and password are required"
        });
    }

    if (
        email.trim().toLowerCase() !== adminEmail.trim().toLowerCase() ||
        password !== adminPassword
    ) {
        return res.status(401).json({
            message: "Invalid email or password"
        });
    }

    const user = {
        id: "admin",
        name: "MITS Admin",
        email: adminEmail.trim().toLowerCase(),
        role: "admin"
    };
    const token = jwt.sign(user, secret, { expiresIn: "1d" });

    res.json({
        message: "Admin login successful",
        token,
        user
    });
});

function verifyRole(role) {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).json({
                message: `${role === "admin" ? "Admin" : "Student"} access required`
            });
        }
        next();
    };
}

function normalizeItem(row) {
    return {
        id: row.id,
        itemName: row.itemName,
        type: row.type,
        category: row.category,
        description: row.description,
        location: row.location,
        date: row.date,
        color: row.color,
        brand: row.brand,
        image: row.image,
        status: row.status,
        createdAt: row.createdAt,
        userName: row.userName,
        userEmail: row.userEmail,
        rollNumber: row.rollNumber,
        phone: row.phone,
        branch: row.branch
    };
}

app.get("/api/items", verifyToken, (req, res) => {
    const includeReporter = req.user.role === "admin";
    const reporterColumns = includeReporter
        ? ", users.name AS userName, users.email AS userEmail, " +
          "users.roll_number AS rollNumber, users.phone, users.branch"
        : "";
    const userJoin = includeReporter
        ? " JOIN users ON users.id = items.user_id"
        : "";
    const sql = `
        SELECT items.id, items.item_name AS itemName, items.type,
               items.category, items.description, items.location,
               items.item_date AS date, items.color, items.brand,
               items.image, items.status, items.created_at AS createdAt
               ${reporterColumns}
        FROM items${userJoin}
        WHERE items.status != 'removed'
        ORDER BY items.created_at DESC
    `;

    db.query(sql, (err, results) => {
        if (err) {
            console.error("Fetch items error:", err.message);
            return res.status(500).json({
                message: "Could not retrieve items"
            });
        }

        res.json({ items: results.map(normalizeItem) });
    });
});

app.get("/api/my-items", verifyToken, verifyRole("student"), (req, res) => {
    const sql = `
        SELECT items.id, items.item_name AS itemName, items.type,
               items.category, items.description, items.location,
               items.item_date AS date, items.color, items.brand,
               items.image, items.status, items.created_at AS createdAt,
               users.name AS userName, users.email AS userEmail,
               users.roll_number AS rollNumber, users.phone, users.branch
        FROM items
        JOIN users ON users.id = items.user_id
        WHERE items.user_id = ? AND items.status != 'removed'
        ORDER BY items.created_at DESC
    `;

    db.query(sql, [req.user.id], (err, results) => {
        if (err) {
            console.error("Fetch personal items error:", err.message);
            return res.status(500).json({
                message: "Could not retrieve your reports"
            });
        }

        res.json({ items: results.map(normalizeItem) });
    });
});

app.post("/api/items", verifyToken, verifyRole("student"), (req, res) => {
    const {
        itemName,
        type,
        category,
        description,
        location,
        date,
        color,
        brand,
        image
    } = req.body || {};

    const requiredFields = [itemName, type, category, description, location, date];
    if (
        requiredFields.some((value) => typeof value !== "string" || !value.trim()) ||
        !["lost", "found"].includes(type)
    ) {
        return res.status(400).json({
            message: "Item name, type, category, description, location, and date are required"
        });
    }

    const cleanValues = {
        itemName: itemName.trim(),
        category: category.trim(),
        description: description.trim(),
        location: location.trim(),
        date: date.trim(),
        color: typeof color === "string" ? color.trim() : "",
        brand: typeof brand === "string" ? brand.trim() : "",
        image: typeof image === "string" ? image.trim() : ""
    };

    if (
        cleanValues.itemName.length > 100 ||
        cleanValues.category.length > 50 ||
        cleanValues.description.length > 10000 ||
        cleanValues.location.length > 150 ||
        cleanValues.color.length > 100 ||
        cleanValues.brand.length > 100 ||
        cleanValues.image.length > 255
    ) {
        return res.status(400).json({
            message: "One or more item fields exceed the allowed length"
        });
    }

    const parsedDate = new Date(`${cleanValues.date}T00:00:00.000Z`);
    if (
        !/^\d{4}-\d{2}-\d{2}$/.test(cleanValues.date) ||
        Number.isNaN(parsedDate.getTime()) ||
        parsedDate.toISOString().slice(0, 10) !== cleanValues.date
    ) {
        return res.status(400).json({
            message: "A valid item date is required"
        });
    }

    if (cleanValues.image) {
        try {
            const imageUrl = new URL(cleanValues.image);
            if (!["http:", "https:"].includes(imageUrl.protocol)) {
                throw new Error("Unsupported image URL protocol");
            }
        } catch {
            return res.status(400).json({
                message: "Image must be a valid HTTP or HTTPS URL"
            });
        }
    }

    const sql = `
        INSERT INTO items
        (user_id, item_name, type, category, description, location,
         item_date, color, brand, image)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    db.query(
        sql,
        [
            req.user.id,
            cleanValues.itemName,
            type,
            cleanValues.category,
            cleanValues.description,
            cleanValues.location,
            cleanValues.date,
            cleanValues.color || null,
            cleanValues.brand || null,
            cleanValues.image || null
        ],
        (err, result) => {
            if (err) {
                console.error("Create item error:", err.message);
                return res.status(500).json({
                    message: "Could not save your report"
                });
            }

            res.status(201).json({
                message: "Report saved successfully",
                item: {
                    id: result.insertId,
                    ...cleanValues,
                    type,
                    status: "active"
                }
            });
        }
    );
});

app.delete(
    "/api/items/:id",
    verifyToken,
    verifyRole("admin"),
    (req, res) => {
        const itemId = Number(req.params.id);
        if (!Number.isSafeInteger(itemId) || itemId < 1) {
            return res.status(400).json({
                message: "A valid item ID is required"
            });
        }

        db.query(
            "UPDATE items SET status = 'removed' WHERE id = ? AND status != 'removed'",
            [itemId],
            (err, result) => {
                if (err) {
                    console.error("Remove item error:", err.message);
                    return res.status(500).json({
                        message: "Could not remove item"
                    });
                }

                if (result.affectedRows === 0) {
                    return res.status(404).json({
                        message: "Item not found"
                    });
                }

                res.json({ message: "Item removed successfully" });
            }
        );
    }
);

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
        WHERE role = 'student'
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