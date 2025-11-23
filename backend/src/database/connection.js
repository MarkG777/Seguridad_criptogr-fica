/**
 * Conexión a Base de Datos SQLite
 * Wrapper con promesas para facilitar uso
 */

const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

class Database {
    constructor() {
        this.db = null;
    }

    connect() {
        return new Promise((resolve, reject) => {
            const dbPath = process.env.DB_PATH || path.join(__dirname, '../../database/testamentos.db');
            
            // Verificar que existe el archivo
            if (!fs.existsSync(dbPath)) {
                return reject(new Error('Base de datos no existe. Ejecuta: npm run init-db'));
            }

            this.db = new sqlite3.Database(dbPath, (err) => {
                if (err) {
                    reject(err);
                } else {
                    console.log('Conectado a base de datos SQLite');
                    resolve();
                }
            });
        });
    }

    /**
     * Ejecutar query con parámetros
     */
    run(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.run(sql, params, function(err) {
                if (err) {
                    reject(err);
                } else {
                    resolve({ lastID: this.lastID, changes: this.changes });
                }
            });
        });
    }

    /**
     * Obtener un solo registro
     */
    get(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.get(sql, params, (err, row) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(row);
                }
            });
        });
    }

    /**
     * Obtener múltiples registros
     */
    all(sql, params = []) {
        return new Promise((resolve, reject) => {
            this.db.all(sql, params, (err, rows) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(rows);
                }
            });
        });
    }

    /**
     * Cerrar conexión
     */
    close() {
        return new Promise((resolve, reject) => {
            if (this.db) {
                this.db.close((err) => {
                    if (err) {
                        reject(err);
                    } else {
                        console.log('Conexión a base de datos cerrada');
                        resolve();
                    }
                });
            } else {
                resolve();
            }
        });
    }
}

// Singleton
const database = new Database();

module.exports = database;
