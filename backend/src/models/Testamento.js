/**
 * Modelo de Testamento
 * Operaciones CRUD para la tabla testamentos
 */

const database = require('../database/connection');

class Testamento {

    /**
     * Crear nuevo testamento
     */
    static async create(testamentData) {
        const {
            usuario_id,
            contenido_cifrado,
            iv_contenido,
            cuentas_bancarias_cifradas,
            iv_cuentas,
            titulo
        } = testamentData;
        
        const sql = `
            INSERT INTO testamentos (
                usuario_id,
                contenido_cifrado,
                iv_contenido,
                cuentas_bancarias_cifradas,
                iv_cuentas,
                titulo,
                estado
            ) VALUES (?, ?, ?, ?, ?, ?, 'borrador')
        `;
        
        const result = await database.run(sql, [
            usuario_id,
            contenido_cifrado,
            iv_contenido,
            cuentas_bancarias_cifradas || null,
            iv_cuentas || null,
            titulo || 'Sin título'
        ]);
        
        return result.lastID;
    }

    /**
     * Obtener testamento por ID
     */
    static async findById(id) {
        const sql = `SELECT * FROM testamentos WHERE id = ?`;
        return await database.get(sql, [id]);
    }

    /**
     * Obtener todos los testamentos de un usuario
     */
    static async findByUserId(userId) {
        const sql = `
            SELECT 
                id,
                titulo,
                estado,
                firmado_en,
                created_at,
                updated_at
            FROM testamentos
            WHERE usuario_id = ?
            ORDER BY updated_at DESC
        `;
        return await database.all(sql, [userId]);
    }

    /**
     * Actualizar contenido de testamento
     */
    static async update(id, testamentData) {
        const {
            contenido_cifrado,
            iv_contenido,
            cuentas_bancarias_cifradas,
            iv_cuentas,
            titulo
        } = testamentData;
        
        const sql = `
            UPDATE testamentos
            SET contenido_cifrado = ?,
                iv_contenido = ?,
                cuentas_bancarias_cifradas = ?,
                iv_cuentas = ?,
                titulo = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND estado = 'borrador'
        `;
        
        const result = await database.run(sql, [
            contenido_cifrado,
            iv_contenido,
            cuentas_bancarias_cifradas,
            iv_cuentas,
            titulo,
            id
        ]);
        
        return result.changes > 0;
    }

    /**
     * Firmar testamento
     */
    static async sign(id, signatureData) {
        const { firma_digital, hash_original } = signatureData;
        
        const sql = `
            UPDATE testamentos
            SET firma_digital = ?,
                hash_original = ?,
                firmado_en = CURRENT_TIMESTAMP,
                estado = 'firmado',
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND estado = 'borrador'
        `;
        
        const result = await database.run(sql, [firma_digital, hash_original, id]);
        
        return result.changes > 0;
    }

    /**
     * Verificar propiedad del testamento
     */
    static async verifyOwnership(testamentoId, userId) {
        const sql = `
            SELECT COUNT(*) as count
            FROM testamentos
            WHERE id = ? AND usuario_id = ?
        `;
        const result = await database.get(sql, [testamentoId, userId]);
        return result.count > 0;
    }

    /**
     * Obtener resumen de testamentos (vista)
     */
    static async getResumenByUserId(userId) {
        const sql = `
            SELECT * FROM v_testamentos_resumen
            WHERE usuario_id = ?
            ORDER BY updated_at DESC
        `;
        return await database.all(sql, [userId]);
    }

    /**
     * Eliminar testamento (solo borradores)
     */
    static async delete(id) {
        const sql = `DELETE FROM testamentos WHERE id = ? AND estado = 'borrador'`;
        const result = await database.run(sql, [id]);
        return result.changes > 0;
    }

    /**
     * Cambiar estado a ejecutado
     */
    static async markAsExecuted(id) {
        const sql = `
            UPDATE testamentos
            SET estado = 'ejecutado',
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND estado = 'firmado'
        `;
        const result = await database.run(sql, [id]);
        return result.changes > 0;
    }

    /**
     * Contar testamentos por usuario
     */
    static async countByUserId(userId) {
        const sql = `
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN estado = 'borrador' THEN 1 ELSE 0 END) as borradores,
                SUM(CASE WHEN estado = 'firmado' THEN 1 ELSE 0 END) as firmados,
                SUM(CASE WHEN estado = 'ejecutado' THEN 1 ELSE 0 END) as ejecutados
            FROM testamentos
            WHERE usuario_id = ?
        `;
        return await database.get(sql, [userId]);
    }
}

module.exports = Testamento;
