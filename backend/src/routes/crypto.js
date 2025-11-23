/**
 * Rutas de Criptografía
 * Endpoint para obtener llave pública del servidor
 */

const express = require('express');
const router = express.Router();

const hybridCryptoService = require('../security/HybridCryptoService');
const { generalLimiter } = require('../middleware/security');
const logger = require('../utils/logger');

/**
 * GET /api/crypto/server-public-key
 * Obtener llave pública RSA del servidor
 * CAPA 4: Para cifrado híbrido
 */
router.get('/server-public-key', generalLimiter, (req, res) => {
    try {
        logger.info('[CRYPTO] Enviando llave pública del servidor');
        
        const keyInfo = hybridCryptoService.getServerPublicKey();
        
        res.json({
            success: true,
            ...keyInfo
        });
    } catch (error) {
        logger.error('[CRYPTO] Error al enviar llave pública:', error);
        res.status(500).json({
            success: false,
            error: 'Error al obtener llave pública'
        });
    }
});

module.exports = router;
