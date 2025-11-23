/**
 * CAPA 4: Defensa en Profundidad (Cifrado Híbrido)
 * 
 * Implementa el "Sobre Digital":
 * - Cifrado híbrido RSA + AES para comunicación
 * - Cliente cifra con RSA pública del servidor
 * - Servidor descifra con RSA privada
 * - Datos cifrados con AES-256-GCM (rápido)
 * - Llave AES cifrada con RSA (seguro)
 * 
 * @author Marco Antonio Gómez Olvera
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class HybridCryptoService {

    constructor() {
        this.serverPublicKey = null;
        this.serverPrivateKey = null;
        this.initializeServerKeys();
    }

    /**
     * Inicializar o generar llaves RSA del servidor
     */
    initializeServerKeys() {
        const keysDir = path.join(__dirname, '../../keys');
        const publicKeyPath = path.join(keysDir, 'server_public.pem');
        const privateKeyPath = path.join(keysDir, 'server_private.pem');

        // Crear directorio si no existe
        if (!fs.existsSync(keysDir)) {
            fs.mkdirSync(keysDir, { recursive: true });
            console.log('[HYBRID] Directorio keys/ creado');
        }

        // Verificar si ya existen las llaves
        if (fs.existsSync(publicKeyPath) && fs.existsSync(privateKeyPath)) {
            console.log('[HYBRID] Cargando llaves RSA del servidor...');
            this.serverPublicKey = fs.readFileSync(publicKeyPath, 'utf8');
            this.serverPrivateKey = fs.readFileSync(privateKeyPath, 'utf8');
            console.log('[HYBRID] Llaves RSA del servidor cargadas');
        } else {
            console.log('[HYBRID] Generando nuevas llaves RSA del servidor...');
            this.generateServerKeys();
            
            // Guardar llaves
            fs.writeFileSync(publicKeyPath, this.serverPublicKey, { mode: 0o644 });
            fs.writeFileSync(privateKeyPath, this.serverPrivateKey, { mode: 0o600 });
            console.log('[HYBRID] Llaves RSA del servidor guardadas');
            console.log('[HYBRID] Public key:', publicKeyPath);
            console.log('[HYBRID] Private key:', privateKeyPath);
        }
    }

    /**
     * Generar par de llaves RSA para el servidor
     */
    generateServerKeys() {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });

        this.serverPublicKey = publicKey;
        this.serverPrivateKey = privateKey;
    }

    /**
     * Obtener llave pública del servidor
     * Esta llave se envía al cliente para cifrar
     */
    getServerPublicKey() {
        return {
            publicKey: this.serverPublicKey,
            algorithm: 'RSA-OAEP-2048',
            usage: 'Cifrar llaves AES para comunicación híbrida'
        };
    }

    /**
     * Descifrar "Sobre Digital" recibido del cliente
     * 
     * El cliente envía:
     * - datosCifrados: Datos cifrados con AES-256-GCM
     * - claveAESCifrada: Llave AES cifrada con RSA pública del servidor
     * - iv: Vector de inicialización (12 bytes)
     * - authTag: Tag de autenticación GCM (16 bytes)
     * 
     * @param {object} sobreDigital - Paquete cifrado del cliente
     * @returns {object} Datos descifrados
     */
    decryptDigitalEnvelope(sobreDigital) {
        try {
            console.log('[HYBRID] Descifrando sobre digital...');
            
            const {
                datosCifrados,
                claveAESCifrada,
                iv,
                authTag
            } = sobreDigital;

            // Paso 1: Descifrar llave AES con RSA privada del servidor
            console.log('[HYBRID] 1. Descifrando llave AES con RSA privada del servidor...');
            
            const claveAESBuffer = crypto.privateDecrypt(
                {
                    key: this.serverPrivateKey,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: 'sha256'
                },
                Buffer.from(claveAESCifrada, 'base64')
            );

            console.log('[HYBRID]    ✓ Llave AES descifrada:', claveAESBuffer.length, 'bytes');

            // Paso 2: Descifrar datos con AES-256-GCM
            console.log('[HYBRID] 2. Descifrando datos con AES-256-GCM...');
            
            const decipher = crypto.createDecipheriv(
                'aes-256-gcm',
                claveAESBuffer,
                Buffer.from(iv, 'base64')
            );

            // Establecer auth tag
            decipher.setAuthTag(Buffer.from(authTag, 'base64'));

            // Descifrar
            let datosDescifrados = decipher.update(datosCifrados, 'base64', 'utf8');
            datosDescifrados += decipher.final('utf8');

            console.log('[HYBRID]    ✓ Datos descifrados:', datosDescifrados.length, 'caracteres');

            // Paso 3: Parsear JSON
            const datos = JSON.parse(datosDescifrados);

            console.log('[HYBRID] ✓ Sobre digital descifrado exitosamente');

            return {
                success: true,
                data: datos
            };

        } catch (error) {
            console.error('[HYBRID] Error al descifrar sobre digital:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Cifrar respuesta para el cliente (Sobre Digital inverso)
     * 
     * @param {object} datos - Datos a cifrar
     * @param {string} publicKeyCliente - Llave pública RSA del cliente
     * @returns {object} Sobre digital cifrado
     */
    encryptDigitalEnvelope(datos, publicKeyCliente) {
        try {
            console.log('[HYBRID] Cifrando respuesta para el cliente...');

            // Paso 1: Generar llave AES temporal
            console.log('[HYBRID] 1. Generando llave AES-256 temporal...');
            const claveAES = crypto.randomBytes(32); // 256 bits
            console.log('[HYBRID]    ✓ Llave AES generada:', claveAES.length, 'bytes');

            // Paso 2: Generar IV
            console.log('[HYBRID] 2. Generando IV aleatorio...');
            const iv = crypto.randomBytes(12); // 12 bytes para GCM
            console.log('[HYBRID]    ✓ IV generado:', iv.length, 'bytes');

            // Paso 3: Cifrar datos con AES-256-GCM
            console.log('[HYBRID] 3. Cifrando datos con AES-256-GCM...');
            const datosJSON = JSON.stringify(datos);
            
            const cipher = crypto.createCipheriv('aes-256-gcm', claveAES, iv);
            
            let datosCifrados = cipher.update(datosJSON, 'utf8', 'base64');
            datosCifrados += cipher.final('base64');
            
            const authTag = cipher.getAuthTag();
            console.log('[HYBRID]    ✓ Datos cifrados');

            // Paso 4: Cifrar llave AES con RSA pública del cliente
            console.log('[HYBRID] 4. Cifrando llave AES con RSA pública del cliente...');
            
            const claveAESCifrada = crypto.publicEncrypt(
                {
                    key: publicKeyCliente,
                    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                    oaepHash: 'sha256'
                },
                claveAES
            );

            console.log('[HYBRID]    ✓ Llave AES cifrada');

            console.log('[HYBRID] ✓ Sobre digital creado exitosamente');

            return {
                success: true,
                envelope: {
                    datosCifrados: datosCifrados,
                    claveAESCifrada: claveAESCifrada.toString('base64'),
                    iv: iv.toString('base64'),
                    authTag: authTag.toString('base64')
                }
            };

        } catch (error) {
            console.error('[HYBRID] Error al cifrar sobre digital:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Verificar integridad de sobre digital
     */
    verifyEnvelopeIntegrity(sobreDigital) {
        const required = ['datosCifrados', 'claveAESCifrada', 'iv', 'authTag'];
        
        for (const field of required) {
            if (!sobreDigital[field]) {
                console.error(`[HYBRID] Campo requerido faltante: ${field}`);
                return false;
            }
        }

        return true;
    }

    /**
     * Obtener información del sobre digital
     */
    getEnvelopeInfo(sobreDigital) {
        return {
            datosCifradosLength: sobreDigital.datosCifrados?.length || 0,
            claveAESCifradaLength: sobreDigital.claveAESCifrada?.length || 0,
            ivLength: sobreDigital.iv?.length || 0,
            authTagLength: sobreDigital.authTag?.length || 0,
            completo: this.verifyEnvelopeIntegrity(sobreDigital)
        };
    }
}

// Singleton
const hybridCryptoService = new HybridCryptoService();

module.exports = hybridCryptoService;
