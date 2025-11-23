/**
 * Rutas de Autenticación
 */

const express = require('express');
const router = express.Router();

const authController = require('../controllers/authController');
const { requireAuth } = require('../middleware/auth');
const {
    loginLimiter,
    validateRegister,
    validateLogin,
    handleValidationErrors,
    sanitizeInput,
    logClientInfo
} = require('../middleware/security');

// Middleware global para estas rutas
router.use(logClientInfo);

/**
 * POST /api/auth/register
 * Registrar nuevo usuario
 * CAPA 1: Hash con bcrypt
 * CAPA 3: Genera llaves RSA
 */
router.post('/register',
    loginLimiter,
    sanitizeInput,
    validateRegister,
    handleValidationErrors,
    authController.register
);

/**
 * POST /api/auth/login
 * Login de usuario
 * CAPA 1: Verifica con bcrypt
 */
router.post('/login',
    loginLimiter,
    sanitizeInput,
    validateLogin,
    handleValidationErrors,
    authController.login
);

/**
 * GET /api/auth/me
 * Obtener usuario actual
 * Requiere autenticación JWT
 */
router.get('/me',
    requireAuth,
    authController.getCurrentUser
);

/**
 * POST /api/auth/logout
 * Cerrar sesión
 */
router.post('/logout',
    requireAuth,
    authController.logout
);

module.exports = router;
