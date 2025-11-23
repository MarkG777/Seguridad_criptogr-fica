/**
 * CAPA 2: Datos en Reposo (Cifrado Simétrico)
 * 
 * Implementa:
 * - Cifrado AES-256-CBC para datos en base de datos
 * - Gestión de llave maestra y vectores de inicialización (IV)
 * - Protección de contenido de testamentos y claves bancarias
 * 
 * @author Marco Antonio Gómez Olvera
 */

const crypto = require('crypto');

const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16; // 16 bytes para AES

class EncryptionService {

    constructor() {
        this.masterKey = null;
        this.initializeMasterKey();
    }

    /**
     * Inicializar llave maestra desde variable de entorno
     */
    initializeMasterKey() {
        const keyHex = process.env.DB_ENCRYPTION_KEY;
        
        if (!keyHex) {
            throw new Error('DB_ENCRYPTION_KEY no configurada en .env');
        }

        if (keyHex.length !== 64) { // 32 bytes = 64 hex chars
            throw new Error('DB_ENCRYPTION_KEY debe ser de 64 caracteres hex (32 bytes)');
        }

        this.masterKey = Buffer.from(keyHex, 'hex');
        console.log('[ENCRYPTION] Llave maestra AES-256 inicializada');
        console.log('[ENCRYPTION] Key length:', this.masterKey.length, 'bytes');
    }

    /**
     * Generar vector de inicialización aleatorio
     */
    generateIV() {
        const iv = crypto.randomBytes(IV_LENGTH);
        console.log('[ENCRYPTION] IV generado:', iv.length, 'bytes');
        return iv;
    }

    /**
     * Cifrar datos con AES-256-CBC
     * 
     * @param {string} plaintext - Texto a cifrar
     * @returns {object} { encrypted: string (hex), iv: string (hex) }
     */
    encrypt(plaintext) {
        try {
            console.log('[ENCRYPTION] Cifrando datos con AES-256-CBC...');
            console.log('[ENCRYPTION] Plaintext length:', plaintext.length, 'caracteres');

            // Generar IV único para este dato
            const iv = this.generateIV();

            // Crear cipher
            const cipher = crypto.createCipheriv(ALGORITHM, this.masterKey, iv);

            // Cifrar
            let encrypted = cipher.update(plaintext, 'utf8', 'hex');
            encrypted += cipher.final('hex');

            console.log('[ENCRYPTION] Datos cifrados exitosamente');
            console.log('[ENCRYPTION] Encrypted length:', encrypted.length, 'caracteres hex');

            return {
                encrypted: encrypted,
                iv: iv.toString('hex')
            };
        } catch (error) {
            console.error('[ENCRYPTION] Error al cifrar:', error);
            throw new Error('Error al cifrar datos');
        }
    }

    /**
     * Descifrar datos con AES-256-CBC
     * 
     * @param {string} encryptedHex - Datos cifrados en hexadecimal
     * @param {string} ivHex - Vector de inicialización en hexadecimal
     * @returns {string} Texto descifrado
     */
    decrypt(encryptedHex, ivHex) {
        try {
            console.log('[ENCRYPTION] Descifrando datos con AES-256-CBC...');
            console.log('[ENCRYPTION] Encrypted length:', encryptedHex.length);
            console.log('[ENCRYPTION] IV length:', ivHex.length);

            // Convertir hex a Buffer
            const iv = Buffer.from(ivHex, 'hex');

            // Crear decipher
            const decipher = crypto.createDecipheriv(ALGORITHM, this.masterKey, iv);

            // Descifrar
            let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
            decrypted += decipher.final('utf8');

            console.log('[ENCRYPTION] Datos descifrados exitosamente');
            console.log('[ENCRYPTION] Decrypted length:', decrypted.length, 'caracteres');

            return decrypted;
        } catch (error) {
            console.error('[ENCRYPTION] Error al descifrar:', error);
            throw new Error('Error al descifrar datos');
        }
    }

    /**
     * Cifrar objeto JSON
     */
    encryptJSON(object) {
        const json = JSON.stringify(object);
        return this.encrypt(json);
    }

    /**
     * Descifrar a objeto JSON
     */
    decryptJSON(encryptedHex, ivHex) {
        const json = this.decrypt(encryptedHex, ivHex);
        return JSON.parse(json);
    }

    /**
     * Cifrar array de objetos (ej. cuentas bancarias)
     */
    encryptArray(array) {
        const json = JSON.stringify(array);
        return this.encrypt(json);
    }

    /**
     * Descifrar a array
     */
    decryptArray(encryptedHex, ivHex) {
        const json = this.decrypt(encryptedHex, ivHex);
        return JSON.parse(json);
    }

    /**
     * Generar hash SHA-256 de datos
     * Útil para verificar integridad
     */
    generateHash(data) {
        const hash = crypto.createHash('sha256');
        hash.update(data);
        return hash.digest('hex');
    }

    /**
     * Verificar hash
     */
    verifyHash(data, expectedHash) {
        const actualHash = this.generateHash(data);
        return actualHash === expectedHash;
    }

    /**
     * Cifrar contenido de testamento
     * Wrapper específico para testamentos
     */
    encryptTestamentContent(content) {
        console.log('[ENCRYPTION] Cifrando contenido de testamento...');
        return this.encrypt(content);
    }

    /**
     * Descifrar contenido de testamento
     */
    decryptTestamentContent(encryptedHex, ivHex) {
        console.log('[ENCRYPTION] Descifrando contenido de testamento...');
        return this.decrypt(encryptedHex, ivHex);
    }

    /**
     * Cifrar claves de cuentas bancarias
     */
    encryptBankAccounts(accounts) {
        console.log('[ENCRYPTION] Cifrando claves de cuentas bancarias...');
        console.log('[ENCRYPTION] Número de cuentas:', accounts.length);
        return this.encryptArray(accounts);
    }

    /**
     * Descifrar claves de cuentas bancarias
     */
    decryptBankAccounts(encryptedHex, ivHex) {
        console.log('[ENCRYPTION] Descifrando claves de cuentas bancarias...');
        return this.decryptArray(encryptedHex, ivHex);
    }

    /**
     * Verificar que la llave maestra está configurada
     */
    isConfigured() {
        return this.masterKey !== null && this.masterKey.length === 32;
    }

    /**
     * Rotar llave maestra (para futuras implementaciones)
     * Requeriría re-cifrar todos los datos
     */
    async rotateMasterKey(newKeyHex) {
        console.log('[ENCRYPTION] ADVERTENCIA: Rotación de llave requiere re-cifrar todos los datos');
        // Implementación futura
        throw new Error('Rotación de llave no implementada aún');
    }
}

// Singleton
const encryptionService = new EncryptionService();

module.exports = encryptionService;
