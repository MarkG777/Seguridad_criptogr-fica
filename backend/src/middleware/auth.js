/**
 * Middleware de Autenticación
 * Verifica JWT tokens en las peticiones
 */

const authService = require('../security/AuthService');
const Usuario = require('../models/Usuario');

/**
 * Verificar que el usuario está autenticado
 */
async function requireAuth(req, res, next) {
    try {
        // Obtener token del header
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                error: 'No autorizado - Token requerido'
            });
        }

        const token = authHeader.substring(7); // Remover "Bearer "

        // Verificar token
        const decoded = authService.verifyToken(token);

        // Obtener usuario
        const usuario = await Usuario.findById(decoded.userId);

        if (!usuario) {
            return res.status(401).json({
                success: false,
                error: 'Usuario no encontrado'
            });
        }

        // Agregar usuario al request
        req.user = {
            id: usuario.id,
            username: usuario.username,
            email: usuario.email,
            publicKey: usuario.public_key_pem
        };

        next();
    } catch (error) {
        console.error('[AUTH] Error en middleware:', error);
        
        if (error.message === 'Token expirado') {
            return res.status(401).json({
                success: false,
                error: 'Token expirado',
                code: 'TOKEN_EXPIRED'
            });
        }

        return res.status(401).json({
            success: false,
            error: 'Token inválido'
        });
    }
}

/**
 * Verificar autenticación opcional
 * No falla si no hay token, solo lo agrega si existe
 */
async function optionalAuth(req, res, next) {
    try {
        const authHeader = req.headers.authorization;
        
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.substring(7);
            const decoded = authService.verifyToken(token);
            const usuario = await Usuario.findById(decoded.userId);
            
            if (usuario) {
                req.user = {
                    id: usuario.id,
                    username: usuario.username,
                    email: usuario.email
                };
            }
        }
    } catch (error) {
        // Silenciosamente ignorar errores
        console.log('[AUTH] Token opcional inválido');
    }
    
    next();
}

module.exports = {
    requireAuth,
    optionalAuth
};
