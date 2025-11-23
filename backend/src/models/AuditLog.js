/**
 * Modelo de AuditLog
 * Registro de auditoría de todas las operaciones
 */

const database = require('../database/connection');

class AuditLog {

    /**
     * Registrar evento en audit log
     */
    static async log(logData) {
        const {
            usuario_id,
            accion,
            entidad,
            entidad_id,
            ip_address,
            user_agent,
            detalles,
            exitoso
        } = logData;
        
        const sql = `
            INSERT INTO audit_log (
                usuario_id,
                accion,
                entidad,
                entidad_id,
                ip_address,
                user_agent,
                detalles,
                exitoso
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `;
        
        await database.run(sql, [
            usuario_id || null,
            accion,
            entidad || null,
            entidad_id || null,
            ip_address || null,
            user_agent || null,
            detalles || null,
            exitoso !== false ? 1 : 0
        ]);
    }

    /**
     * Registrar login exitoso
     */
    static async logLogin(userId, ipAddress, userAgent) {
        await this.log({
            usuario_id: userId,
            accion: 'login',
            entidad: 'usuario',
            entidad_id: userId,
            ip_address: ipAddress,
            user_agent: userAgent,
            exitoso: true
        });
    }

    /**
     * Registrar intento de login fallido
     */
    static async logFailedLogin(username, ipAddress, userAgent, reason) {
        await this.log({
            accion: 'login_failed',
            entidad: 'usuario',
            ip_address: ipAddress,
            user_agent: userAgent,
            detalles: JSON.stringify({ username, reason }),
            exitoso: false
        });
    }

    /**
     * Registrar creación de testamento
     */
    static async logTestamentCreated(userId, testamentoId, ipAddress) {
        await this.log({
            usuario_id: userId,
            accion: 'testamento_creado',
            entidad: 'testamento',
            entidad_id: testamentoId,
            ip_address: ipAddress,
            exitoso: true
        });
    }

    /**
     * Registrar firma de testamento
     */
    static async logTestamentSigned(userId, testamentoId, ipAddress) {
        await this.log({
            usuario_id: userId,
            accion: 'testamento_firmado',
            entidad: 'testamento',
            entidad_id: testamentoId,
            ip_address: ipAddress,
            exitoso: true
        });
    }

    /**
     * Registrar acceso a testamento
     */
    static async logTestamentAccessed(userId, testamentoId, ipAddress) {
        await this.log({
            usuario_id: userId,
            accion: 'testamento_consultado',
            entidad: 'testamento',
            entidad_id: testamentoId,
            ip_address: ipAddress,
            exitoso: true
        });
    }

    /**
     * Obtener logs de un usuario
     */
    static async findByUserId(userId, limit = 100) {
        const sql = `
            SELECT *
            FROM audit_log
            WHERE usuario_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        `;
        return await database.all(sql, [userId, limit]);
    }

    /**
     * Obtener logs de un testamento
     */
    static async findByTestamentoId(testamentoId) {
        const sql = `
            SELECT *
            FROM audit_log
            WHERE entidad = 'testamento' AND entidad_id = ?
            ORDER BY timestamp DESC
        `;
        return await database.all(sql, [testamentoId]);
    }

    /**
     * Obtener logs recientes
     */
    static async getRecent(limit = 50) {
        const sql = `
            SELECT * FROM audit_log
            ORDER BY timestamp DESC
            LIMIT ?
        `;
        return await database.all(sql, [limit]);
    }

    /**
     * Obtener intentos de login fallidos recientes
     */
    static async getFailedLogins(limit = 20) {
        const sql = `
            SELECT * FROM audit_log
            WHERE accion = 'login_failed'
            ORDER BY timestamp DESC
            LIMIT ?
        `;
        return await database.all(sql, [limit]);
    }
}

module.exports = AuditLog;
