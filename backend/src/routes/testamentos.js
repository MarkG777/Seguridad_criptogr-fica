/**
 * Rutas de Testamentos
 */

const express = require('express');
const router = express.Router();

const testamentoController = require('../controllers/testamentoController');
const { requireAuth } = require('../middleware/auth');
const {
    generalLimiter,
    signatureLimiter,
    validateTestamento,
    validateSignature,
    handleValidationErrors,
    logClientInfo
} = require('../middleware/security');

// Middleware global para estas rutas
router.use(requireAuth);
router.use(logClientInfo);

/**
 * POST /api/testamentos/crear
 * Crear nuevo testamento
 * CAPA 4: Recibe cifrado híbrido
 * CAPA 2: Guarda cifrado AES-256
 */
router.post('/crear',
    generalLimiter,
    validateTestamento,
    handleValidationErrors,
    testamentoController.crear
);

/**
 * GET /api/testamentos/mis-testamentos
 * Listar testamentos del usuario
 */
router.get('/mis-testamentos',
    generalLimiter,
    testamentoController.listar
);

/**
 * GET /api/testamentos/:id
 * Obtener testamento por ID
 * CAPA 2: Descifra de BD
 * CAPA 4: Envía cifrado híbrido
 */
router.get('/:id',
    generalLimiter,
    testamentoController.obtener
);

/**
 * PUT /api/testamentos/:id
 * Actualizar testamento (solo borradores)
 * CAPA 4: Recibe cifrado híbrido
 * CAPA 2: Actualiza cifrado en BD
 */
router.put('/:id',
    generalLimiter,
    validateTestamento,
    handleValidationErrors,
    testamentoController.actualizar
);

/**
 * POST /api/testamentos/:id/firmar
 * Firmar testamento
 * CAPA 3: Firma digital RSA
 * CAPA 4: Recibe cifrado híbrido
 */
router.post('/:id/firmar',
    signatureLimiter,
    validateSignature,
    handleValidationErrors,
    testamentoController.firmar
);

/**
 * DELETE /api/testamentos/:id
 * Eliminar testamento (solo borradores)
 */
router.delete('/:id',
    generalLimiter,
    testamentoController.eliminar
);

module.exports = router;
