/**
 * Inicializador de Base de Datos
 * Crea las tablas y estructura inicial
 */

const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');

// Asegurar que existe el directorio database
const dbDir = path.join(__dirname, '../../database');
if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
    console.log('Directorio database/ creado');
}

const dbPath = path.join(dbDir, 'testamentos.db');
const schemaPath = path.join(__dirname, 'schema.sql');

console.log('\n==========================================================');
console.log('  INICIALIZANDO BASE DE DATOS');
console.log('==========================================================\n');

// Leer el schema SQL
const schema = fs.readFileSync(schemaPath, 'utf8');

// Crear/abrir base de datos
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error al abrir base de datos:', err);
        process.exit(1);
    }
    console.log('Base de datos abierta:', dbPath);
});

// Ejecutar el schema
db.exec(schema, (err) => {
    if (err) {
        console.error('Error al ejecutar schema:', err);
        process.exit(1);
    }
    
    console.log('\nTablas creadas exitosamente:');
    console.log('  - usuarios (con password_hash bcrypt)');
    console.log('  - testamentos (con contenido cifrado AES-256)');
    console.log('  - beneficiarios (con datos cifrados)');
    console.log('  - mensajes_postumos (cifrados)');
    console.log('  - audit_log');
    console.log('  - sesiones');
    
    // Verificar tablas
    db.all("SELECT name FROM sqlite_master WHERE type='table'", [], (err, tables) => {
        if (err) {
            console.error('Error al verificar tablas:', err);
        } else {
            console.log('\nTablas en la base de datos:');
            tables.forEach(table => {
                console.log('  - ' + table.name);
            });
        }
        
        // Cerrar conexión
        db.close((err) => {
            if (err) {
                console.error('Error al cerrar base de datos:', err);
            } else {
                console.log('\n==========================================================');
                console.log('  BASE DE DATOS INICIALIZADA CORRECTAMENTE');
                console.log('==========================================================\n');
            }
        });
    });
});
