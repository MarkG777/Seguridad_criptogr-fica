/**
 * Rutas de Verificación
 * Endpoint público para verificar firmas
 */

const express = require('express');
const router = express.Router();

const verificacionController = require('../controllers/verificacionController');
const { generalLimiter, logClientInfo } = require('../middleware/security');
const { body } = require('express-validator');
const { handleValidationErrors } = require('../middleware/security');

// Middleware global
router.use(logClientInfo);

/**
 * POST /api/verificar/firma
 * Verificar firma digital de un testamento
 * CAPA 3: Verifica firma RSA
 * Endpoint público (no requiere auth)
 */
router.post('/firma',
    generalLimiter,
    body('testamento_id').isInt().withMessage('ID de testamento inválido'),
    handleValidationErrors,
    verificacionController.verificarFirma
);

/**
 * GET /api/verificar/info/:id
 * Obtener información pública de un testamento
 * No requiere autenticación
 */
router.get('/info/:id',
    generalLimiter,
    verificacionController.obtenerInfo
);

module.exports = router;
