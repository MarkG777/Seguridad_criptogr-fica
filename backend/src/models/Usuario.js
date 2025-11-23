/**
 * Modelo de Usuario
 * Operaciones CRUD para la tabla usuarios
 */

const database = require('../database/connection');

class Usuario {

    /**
     * Crear nuevo usuario
     */
    static async create(userData) {
        const { username, email, password_hash, public_key_pem } = userData;
        
        const sql = `
            INSERT INTO usuarios (username, email, password_hash, public_key_pem)
            VALUES (?, ?, ?, ?)
        `;
        
        const result = await database.run(sql, [username, email, password_hash, public_key_pem]);
        
        return {
            id: result.lastID,
            username,
            email
        };
    }

    /**
     * Buscar usuario por username
     */
    static async findByUsername(username) {
        const sql = `SELECT * FROM usuarios WHERE username = ? AND activo = 1`;
        return await database.get(sql, [username]);
    }

    /**
     * Buscar usuario por email
     */
    static async findByEmail(email) {
        const sql = `SELECT * FROM usuarios WHERE email = ? AND activo = 1`;
        return await database.get(sql, [email]);
    }

    /**
     * Buscar usuario por ID
     */
    static async findById(id) {
        const sql = `SELECT * FROM usuarios WHERE id = ? AND activo = 1`;
        return await database.get(sql, [id]);
    }

    /**
     * Actualizar último login
     */
    static async updateLastLogin(userId) {
        const sql = `UPDATE usuarios SET last_login = CURRENT_TIMESTAMP WHERE id = ?`;
        await database.run(sql, [userId]);
    }

    /**
     * Verificar si existe username
     */
    static async usernameExists(username) {
        const sql = `SELECT COUNT(*) as count FROM usuarios WHERE username = ?`;
        const result = await database.get(sql, [username]);
        return result.count > 0;
    }

    /**
     * Verificar si existe email
     */
    static async emailExists(email) {
        const sql = `SELECT COUNT(*) as count FROM usuarios WHERE email = ?`;
        const result = await database.get(sql, [email]);
        return result.count > 0;
    }

    /**
     * Obtener llave pública del usuario
     */
    static async getPublicKey(userId) {
        const sql = `SELECT public_key_pem FROM usuarios WHERE id = ?`;
        const result = await database.get(sql, [userId]);
        return result?.public_key_pem || null;
    }

    /**
     * Listar todos los usuarios (admin)
     */
    static async findAll() {
        const sql = `
            SELECT id, username, email, created_at, last_login, activo
            FROM usuarios
            ORDER BY created_at DESC
        `;
        return await database.all(sql);
    }

    /**
     * Desactivar usuario
     */
    static async deactivate(userId) {
        const sql = `UPDATE usuarios SET activo = 0 WHERE id = ?`;
        await database.run(sql, [userId]);
    }
}

module.exports = Usuario;
