/**
 * CAPA 3: Autenticidad y No Repudio (Firma Digital)
 * 
 * Implementa:
 * - Firma digital con RSA-2048
 * - Verificación de firma
 * - Hash SHA-256 del contenido
 * - Garantía de autoría y no repudio
 * 
 * @author Marco Antonio Gómez Olvera
 */

const crypto = require('crypto');

class SignatureService {

    /**
     * Generar hash SHA-256 del contenido
     * Este hash es el que se firma
     */
    generateContentHash(content) {
        console.log('[SIGNATURE] Generando hash SHA-256 del contenido...');
        console.log('[SIGNATURE] Content length:', content.length);
        
        const hash = crypto.createHash('sha256');
        hash.update(content, 'utf8');
        const digest = hash.digest('hex');
        
        console.log('[SIGNATURE] Hash generado:', digest.substring(0, 16) + '...');
        return digest;
    }

    /**
     * Firmar contenido con llave privada RSA
     * 
     * @param {string} content - Contenido a firmar
     * @param {string} privateKeyPem - Llave privada en formato PEM
     * @returns {object} { signature: string (base64), hash: string (hex) }
     */
    signContent(content, privateKeyPem) {
        try {
            console.log('[SIGNATURE] Firmando contenido...');
            console.log('[SIGNATURE] Content length:', content.length);

            // Generar hash del contenido
            const hash = this.generateContentHash(content);

            // Firmar el hash
            const sign = crypto.createSign('SHA256');
            sign.update(content);
            sign.end();

            const signature = sign.sign({
                key: privateKeyPem,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN
            });

            const signatureBase64 = signature.toString('base64');

            console.log('[SIGNATURE] Firma generada exitosamente');
            console.log('[SIGNATURE] Signature length:', signatureBase64.length, 'caracteres');
            console.log('[SIGNATURE] Hash:', hash.substring(0, 16) + '...');

            return {
                signature: signatureBase64,
                hash: hash
            };
        } catch (error) {
            console.error('[SIGNATURE] Error al firmar contenido:', error);
            throw new Error('Error al generar firma digital');
        }
    }

    /**
     * Verificar firma digital
     * 
     * @param {string} content - Contenido original
     * @param {string} signatureBase64 - Firma en base64
     * @param {string} publicKeyPem - Llave pública en formato PEM
     * @param {string} expectedHash - Hash esperado (opcional, para doble verificación)
     * @returns {boolean} true si la firma es válida
     */
    verifySignature(content, signatureBase64, publicKeyPem, expectedHash = null) {
        try {
            console.log('[SIGNATURE] Verificando firma digital...');
            console.log('[SIGNATURE] Content length:', content.length);
            console.log('[SIGNATURE] Signature length:', signatureBase64.length);

            // Si se proporciona hash esperado, verificarlo primero
            if (expectedHash) {
                const actualHash = this.generateContentHash(content);
                if (actualHash !== expectedHash) {
                    console.error('[SIGNATURE] Hash no coincide - contenido modificado');
                    return false;
                }
                console.log('[SIGNATURE] Hash verificado correctamente');
            }

            // Verificar firma
            const verify = crypto.createVerify('SHA256');
            verify.update(content);
            verify.end();

            const signature = Buffer.from(signatureBase64, 'base64');

            const isValid = verify.verify({
                key: publicKeyPem,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN
            }, signature);

            console.log('[SIGNATURE] Firma válida:', isValid);
            
            if (isValid) {
                console.log('[SIGNATURE] ✓ Firma verificada exitosamente');
                console.log('[SIGNATURE] ✓ Autoría confirmada');
                console.log('[SIGNATURE] ✓ Integridad garantizada');
                console.log('[SIGNATURE] ✓ No repudio asegurado');
            } else {
                console.error('[SIGNATURE] ✗ Firma inválida');
            }

            return isValid;
        } catch (error) {
            console.error('[SIGNATURE] Error al verificar firma:', error);
            return false;
        }
    }

    /**
     * Firmar hash directamente (útil cuando ya tenemos el hash)
     */
    signHash(hash, privateKeyPem) {
        try {
            console.log('[SIGNATURE] Firmando hash directamente...');
            
            const sign = crypto.createSign('SHA256');
            sign.update(hash);
            sign.end();

            const signature = sign.sign({
                key: privateKeyPem,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING
            });

            return signature.toString('base64');
        } catch (error) {
            console.error('[SIGNATURE] Error al firmar hash:', error);
            throw new Error('Error al firmar hash');
        }
    }

    /**
     * Crear "paquete de firma" completo
     * Incluye contenido, firma, hash y timestamp
     */
    createSignaturePackage(content, privateKeyPem) {
        const { signature, hash } = this.signContent(content, privateKeyPem);
        const timestamp = new Date().toISOString();

        return {
            content: content,
            signature: signature,
            hash: hash,
            timestamp: timestamp,
            algorithm: 'RSA-PSS-SHA256'
        };
    }

    /**
     * Verificar paquete de firma completo
     */
    verifySignaturePackage(package_, publicKeyPem) {
        const { content, signature, hash } = package_;
        return this.verifySignature(content, signature, publicKeyPem, hash);
    }

    /**
     * Generar información de firma para mostrar al usuario
     */
    getSignatureInfo(signatureBase64) {
        const buffer = Buffer.from(signatureBase64, 'base64');
        return {
            length: buffer.length,
            algorithm: 'RSA-PSS-SHA256',
            format: 'base64',
            preview: signatureBase64.substring(0, 32) + '...'
        };
    }

    /**
     * Verificar que una llave pública es válida
     */
    validatePublicKey(publicKeyPem) {
        try {
            // Intentar crear un objeto de llave
            crypto.createPublicKey(publicKeyPem);
            return true;
        } catch (error) {
            console.error('[SIGNATURE] Llave pública inválida:', error);
            return false;
        }
    }

    /**
     * Verificar que una llave privada es válida
     */
    validatePrivateKey(privateKeyPem) {
        try {
            // Intentar crear un objeto de llave
            crypto.createPrivateKey(privateKeyPem);
            return true;
        } catch (error) {
            console.error('[SIGNATURE] Llave privada inválida:', error);
            return false;
        }
    }

    /**
     * Comparar hashes de forma segura (timing attack resistant)
     */
    compareHashes(hash1, hash2) {
        if (hash1.length !== hash2.length) {
            return false;
        }
        
        return crypto.timingSafeEqual(
            Buffer.from(hash1, 'hex'),
            Buffer.from(hash2, 'hex')
        );
    }
}

// Singleton
const signatureService = new SignatureService();

module.exports = signatureService;
