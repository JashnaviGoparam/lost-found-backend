require("dotenv").config();
const mysql = require("mysql2/promise");

async function createTables() {
    let connection;

    try {
        connection = await mysql.createConnection({
            host: process.env.DB_HOST,
            port: Number(process.env.DB_PORT || 3306),
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            database: process.env.DB_NAME,
            ssl: process.env.DB_SSL === "true"
                ? { rejectUnauthorized: false }
                : undefined
        });

        console.log("Connected to MySQL!");

        await connection.query(
            "CREATE TABLE IF NOT EXISTS users (" +
            "id INT AUTO_INCREMENT PRIMARY KEY, " +
            "name VARCHAR(100) NOT NULL, " +
            "roll_number VARCHAR(50) UNIQUE NOT NULL, " +
            "email VARCHAR(100) UNIQUE NOT NULL, " +
            "phone VARCHAR(15), " +
            "branch VARCHAR(50), " +
            "password VARCHAR(255) NOT NULL, " +
            "role ENUM('student', 'admin') DEFAULT 'student', " +
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        );

        await connection.query(
            "CREATE TABLE IF NOT EXISTS password_resets (" +
            "id INT AUTO_INCREMENT PRIMARY KEY, " +
            "user_id INT NOT NULL, " +
            "token_hash CHAR(64) NOT NULL UNIQUE, " +
            "expires_at DATETIME NOT NULL, " +
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
            "FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)"
        );

        await connection.query(
            "CREATE TABLE IF NOT EXISTS items (" +
            "id INT AUTO_INCREMENT PRIMARY KEY, " +
            "user_id INT NOT NULL, " +
            "item_name VARCHAR(100) NOT NULL, " +
            "type ENUM('lost', 'found') NOT NULL, " +
            "category VARCHAR(50) NOT NULL, " +
            "description TEXT, " +
            "location VARCHAR(150), " +
            "item_date DATE, " +
            "image VARCHAR(255), " +
            "status ENUM('active', 'matched', 'claimed', 'recovered', 'removed') DEFAULT 'active', " +
            "verification_status ENUM('pending', 'verified', 'rejected') DEFAULT 'pending', " +
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
            "FOREIGN KEY (user_id) REFERENCES users(id))"
        );

        for (const column of ["color", "brand"]) {
            const [existingColumn] = await connection.query(
                "SHOW COLUMNS FROM items LIKE ?",
                [column]
            );

            if (existingColumn.length === 0) {
                await connection.query(
                    `ALTER TABLE items ADD COLUMN ${column} VARCHAR(100) NULL`
                );
            }
        }

        await connection.query(
            "CREATE TABLE IF NOT EXISTS notifications (" +
            "id INT AUTO_INCREMENT PRIMARY KEY, " +
            "user_id INT NOT NULL, " +
            "item_id INT, " +
            "message TEXT NOT NULL, " +
            "type VARCHAR(50), " +
            "is_read BOOLEAN DEFAULT FALSE, " +
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
            "FOREIGN KEY (user_id) REFERENCES users(id), " +
            "FOREIGN KEY (item_id) REFERENCES items(id))"
        );

        await connection.query(
            "CREATE TABLE IF NOT EXISTS messages (" +
            "id INT AUTO_INCREMENT PRIMARY KEY, " +
            "sender_id INT NOT NULL, " +
            "receiver_id INT NOT NULL, " +
            "item_id INT, " +
            "message TEXT NOT NULL, " +
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
            "FOREIGN KEY (sender_id) REFERENCES users(id), " +
            "FOREIGN KEY (receiver_id) REFERENCES users(id), " +
            "FOREIGN KEY (item_id) REFERENCES items(id))"
        );

        const [tables] = await connection.query("SHOW TABLES");

        console.log("Tables created or already exist:");
        console.table(tables);

    } catch (error) {
        console.error("Database error:", error.message);
        process.exitCode = 1;
    } finally {
        if (connection) {
            await connection.end();
        }
    }
}

createTables();
