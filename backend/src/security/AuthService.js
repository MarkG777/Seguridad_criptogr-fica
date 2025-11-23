/**
 * CAPA 1: Login Seguro (Autenticación)
 * 
 * Implementa:
 * - Hash de contraseñas con bcrypt
 * - Generación de JWT tokens
 * - Verificación de credenciales
 * 
 * @author Marco Antonio Gómez Olvera
 */

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const SALT_ROUNDS = 10;
const JWT_EXPIRATION = '24h';

class AuthService {
    
    /**
     * Hashear contraseña con bcrypt
     * NUNCA almacenar contraseñas en texto plano
     */
    async hashPassword(password) {
        try {
            console.log('[AUTH] Hasheando contraseña con bcrypt...');
            const hash = await bcrypt.hash(password, SALT_ROUNDS);
            console.log('[AUTH] Hash generado exitosamente');
            console.log('[AUTH] Hash length:', hash.length);
            console.log('[AUTH] Hash prefix:', hash.substring(0, 7)); // $2b$10$
            return hash;
        } catch (error) {
            console.error('[AUTH] Error al hashear contraseña:', error);
            throw new Error('Error al procesar contraseña');
        }
    }

    /**
     * Verificar contraseña con bcrypt
     */
    async verifyPassword(password, hash) {
        try {
            console.log('[AUTH] Verificando contraseña con bcrypt...');
            const match = await bcrypt.compare(password, hash);
            console.log('[AUTH] Contraseña válida:', match);
            return match;
        } catch (error) {
            console.error('[AUTH] Error al verificar contraseña:', error);
            return false;
        }
    }

    /**
     * Generar par de llaves RSA para usuario
     * Usado para firma digital de testamentos (CAPA 3)
     */
    generateUserKeyPair() {
        console.log('[AUTH] Generando par de llaves RSA para usuario...');
        
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

        console.log('[AUTH] Par de llaves RSA generado');
        console.log('[AUTH] Public key length:', publicKey.length);
        
        return {
            publicKey,
            privateKey
        };
    }

    /**
     * Generar JWT token
     */
    generateToken(payload) {
        try {
            const jwtSecret = process.env.JWT_SECRET;
            
            if (!jwtSecret) {
                throw new Error('JWT_SECRET no configurado');
            }

            console.log('[AUTH] Generando JWT token...');
            
            const token = jwt.sign(
                payload,
                jwtSecret,
                { 
                    expiresIn: JWT_EXPIRATION,
                    issuer: 'testamentos-digitales',
                    audience: 'testamentos-api'
                }
            );

            console.log('[AUTH] Token JWT generado');
            console.log('[AUTH] Token expira en:', JWT_EXPIRATION);
            
            return token;
        } catch (error) {
            console.error('[AUTH] Error al generar token:', error);
            throw new Error('Error al generar token de sesión');
        }
    }

    /**
     * Verificar JWT token
     */
    verifyToken(token) {
        try {
            const jwtSecret = process.env.JWT_SECRET;
            
            if (!jwtSecret) {
                throw new Error('JWT_SECRET no configurado');
            }

            console.log('[AUTH] Verificando JWT token...');
            
            const decoded = jwt.verify(token, jwtSecret, {
                issuer: 'testamentos-digitales',
                audience: 'testamentos-api'
            });

            console.log('[AUTH] Token válido para usuario:', decoded.userId);
            
            return decoded;
        } catch (error) {
            if (error.name === 'TokenExpiredError') {
                console.error('[AUTH] Token expirado');
                throw new Error('Token expirado');
            } else if (error.name === 'JsonWebTokenError') {
                console.error('[AUTH] Token inválido');
                throw new Error('Token inválido');
            } else {
                console.error('[AUTH] Error al verificar token:', error);
                throw new Error('Error al verificar token');
            }
        }
    }

    /**
     * Generar ID único para token (para tabla sesiones)
     */
    generateTokenId() {
        return crypto.randomBytes(16).toString('hex');
    }

    /**
     * Validar formato de email
     */
    validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    /**
     * Validar fortaleza de contraseña
     */
    validatePasswordStrength(password) {
        const errors = [];

        if (password.length < 8) {
            errors.push('La contraseña debe tener al menos 8 caracteres');
        }

        if (!/[A-Z]/.test(password)) {
            errors.push('La contraseña debe contener al menos una letra mayúscula');
        }

        if (!/[a-z]/.test(password)) {
            errors.push('La contraseña debe contener al menos una letra minúscula');
        }

        if (!/[0-9]/.test(password)) {
            errors.push('La contraseña debe contener al menos un número');
        }

        if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
            errors.push('La contraseña debe contener al menos un carácter especial');
        }

        return {
            valid: errors.length === 0,
            errors: errors
        };
    }

    /**
     * Sanitizar username (solo alfanuméricos y guiones)
     */
    sanitizeUsername(username) {
        return username.toLowerCase().replace(/[^a-z0-9_-]/g, '');
    }
}

// Singleton
const authService = new AuthService();

module.exports = authService;
