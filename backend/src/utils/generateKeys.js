/**
 * Script para generar llaves para .env
 * Ejecutar: node src/utils/generateKeys.js
 */

const crypto = require('crypto');

console.log('\n==========================================================');
console.log('  GENERADOR DE LLAVES PARA .ENV');
console.log('==========================================================\n');

// Generar JWT_SECRET (64 bytes)
const jwtSecret = crypto.randomBytes(64).toString('hex');
console.log('JWT_SECRET (copiar a .env):');
console.log(jwtSecret);
console.log('\n');

// Generar DB_ENCRYPTION_KEY (32 bytes para AES-256)
const dbEncryptionKey = crypto.randomBytes(32).toString('hex');
console.log('DB_ENCRYPTION_KEY (copiar a .env):');
console.log(dbEncryptionKey);
console.log('\n');

console.log('==========================================================');
console.log('  INSTRUCCIONES');
console.log('==========================================================\n');
console.log('1. Copia estos valores a tu archivo .env');
console.log('2. NUNCA compartas estas llaves');
console.log('3. NUNCA las subas a Git');
console.log('4. Guarda un backup en ubicación segura');
console.log('\n==========================================================\n');
