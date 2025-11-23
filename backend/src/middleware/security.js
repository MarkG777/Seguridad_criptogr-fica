/**
 * Middleware de Seguridad
 * Rate limiting, validación, sanitización
 */

const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

/**
 * Rate limiter general
 */
const generalLimiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 60000, // 1 minuto
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
    message: {
        success: false,
        error: 'Demasiadas peticiones. Por favor, intenta más tarde.'
    },
    standardHeaders: true,
    legacyHeaders: false
});

/**
 * Rate limiter para login (más restrictivo)
 */
const loginLimiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_LOGIN_WINDOW_MS) || 900000, // 15 minutos
    max: parseInt(process.env.RATE_LIMIT_LOGIN_MAX) || 5,
    message: {
        success: false,
        error: 'Demasiados intentos de login. Por favor, espera 15 minutos.'
    },
    standardHeaders: true,
    legacyHeaders: false
});

/**
 * Rate limiter para firmas (muy restrictivo)
 */
const signatureLimiter = rateLimit({
    windowMs: 60000, // 1 minuto
    max: 10,
    message: {
        success: false,
        error: 'Demasiadas operaciones de firma. Por favor, espera.'
    }
});

/**
 * Validaciones para registro
 */
const validateRegister = [
    body('username')
        .trim()
        .isLength({ min: 3, max: 30 })
        .withMessage('Username debe tener entre 3 y 30 caracteres')
        .matches(/^[a-zA-Z0-9_-]+$/)
        .withMessage('Username solo puede contener letras, números, guiones y guiones bajos'),
    
    body('email')
        .trim()
        .isEmail()
        .normalizeEmail()
        .withMessage('Email inválido'),
    
    body('password')
        .isLength({ min: 8 })
        .withMessage('Contraseña debe tener al menos 8 caracteres')
        .matches(/[A-Z]/)
        .withMessage('Contraseña debe contener al menos una mayúscula')
        .matches(/[a-z]/)
        .withMessage('Contraseña debe contener al menos una minúscula')
        .matches(/[0-9]/)
        .withMessage('Contraseña debe contener al menos un número')
];

/**
 * Validaciones para login
 */
const validateLogin = [
    body('username')
        .trim()
        .notEmpty()
        .withMessage('Username requerido'),
    
    body('password')
        .notEmpty()
        .withMessage('Contraseña requerida')
];

/**
 * Validaciones para crear testamento
 */
const validateTestamento = [
    body('datosCifrados')
        .notEmpty()
        .withMessage('Datos cifrados requeridos'),
    
    body('claveAESCifrada')
        .notEmpty()
        .withMessage('Clave AES cifrada requerida'),
    
    body('iv')
        .notEmpty()
        .withMessage('IV requerido'),
    
    body('authTag')
        .notEmpty()
        .withMessage('Auth tag requerido')
];

/**
 * Validaciones para firma
 */
const validateSignature = [
    body('datosCifrados')
        .notEmpty()
        .withMessage('Datos cifrados requeridos'),
    
    body('claveAESCifrada')
        .notEmpty()
        .withMessage('Clave AES cifrada requerida')
];

/**
 * Manejar errores de validación
 */
function handleValidationErrors(req, res, next) {
    const errors = validationResult(req);
    
    if (!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            error: 'Errores de validación',
            errors: errors.array().map(err => ({
                field: err.param,
                message: err.msg
            }))
        });
    }
    
    next();
}

/**
 * Sanitizar entrada
 */
function sanitizeInput(req, res, next) {
    // Remover caracteres potencialmente peligrosos de ciertos campos
    if (req.body.username) {
        req.body.username = req.body.username.replace(/[<>\"']/g, '');
    }
    
    if (req.body.email) {
        req.body.email = req.body.email.replace(/[<>\"']/g, '');
    }
    
    next();
}

/**
 * Registrar IP del cliente
 */
function logClientInfo(req, res, next) {
    req.clientIp = req.ip || req.connection.remoteAddress;
    req.userAgent = req.headers['user-agent'] || 'Unknown';
    next();
}

/**
 * Manejo global de errores
 */
function errorHandler(err, req, res, next) {
    console.error('[ERROR]', err);
    
    // No exponer detalles del error en producción
    const isDev = process.env.NODE_ENV === 'development';
    
    res.status(err.status || 500).json({
        success: false,
        error: isDev ? err.message : 'Error interno del servidor',
        ...(isDev && { stack: err.stack })
    });
}

module.exports = {
    generalLimiter,
    loginLimiter,
    signatureLimiter,
    validateRegister,
    validateLogin,
    validateTestamento,
    validateSignature,
    handleValidationErrors,
    sanitizeInput,
    logClientInfo,
    errorHandler
};
