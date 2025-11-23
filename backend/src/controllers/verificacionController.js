/**
 * Controlador de Verificación
 * Verificación pública de firmas digitales
 */

const signatureService = require('../security/SignatureService');
const encryptionService = require('../security/EncryptionService');
const Testamento = require('../models/Testamento');
const Usuario = require('../models/Usuario');
const logger = require('../utils/logger');

/**
 * Verificar firma de un testamento
 * POST /api/verificar/firma
 * 
 * Endpoint público para verificar autenticidad de firmas
 */
async function verificarFirma(req, res) {
    try {
        const { testamento_id } = req.body;

        logger.info('[VERIFICACION] Verificando firma de testamento:', testamento_id);

        // Obtener testamento
        const testamento = await Testamento.findById(testamento_id);

        if (!testamento) {
            return res.status(404).json({
                success: false,
                error: 'Testamento no encontrado'
            });
        }

        if (!testamento.firma_digital) {
            return res.status(400).json({
                success: false,
                error: 'El testamento no está firmado'
            });
        }

        // Obtener usuario firmante
        const usuario = await Usuario.findById(testamento.usuario_id);

        if (!usuario) {
            return res.status(404).json({
                success: false,
                error: 'Usuario no encontrado'
            });
        }

        // Descifrar contenido original
        logger.info('[VERIFICACION] Descifrando contenido original...');
        const contenidoOriginal = encryptionService.decryptTestamentContent(
            testamento.contenido_cifrado,
            testamento.iv_contenido
        );

        // CAPA 3: Verificar firma digital
        logger.info('[VERIFICACION] Verificando firma digital con llave pública...');
        
        const firmaValida = signatureService.verifySignature(
            contenidoOriginal,
            testamento.firma_digital,
            usuario.public_key_pem,
            testamento.hash_original
        );

        if (firmaValida) {
            logger.info('[VERIFICACION] Firma válida - Testamento auténtico');
        } else {
            logger.warn('[VERIFICACION] Firma inválida - Testamento comprometido');
        }

        res.json({
            success: true,
            valido: firmaValida,
            testamento: {
                id: testamento.id,
                titulo: testamento.titulo,
                estado: testamento.estado,
                firmado_en: testamento.firmado_en
            },
            firmante: {
                username: usuario.username,
                email: usuario.email
            },
            verificacion: {
                firma_valida: firmaValida,
                integridad: firmaValida ? 'INTACTA' : 'COMPROMETIDA',
                autenticidad: firmaValida ? 'CONFIRMADA' : 'NO CONFIRMADA',
                no_repudio: firmaValida
            }
        });

    } catch (error) {
        logger.error('[VERIFICACION] Error:', error);
        res.status(500).json({
            success: false,
            error: 'Error al verificar firma'
        });
    }
}

/**
 * Obtener información de un testamento firmado (sin contenido sensible)
 * GET /api/verificar/info/:id
 */
async function obtenerInfo(req, res) {
    try {
        const testamentoId = req.params.id;

        logger.info('[VERIFICACION] Obteniendo info de testamento:', testamentoId);

        const testamento = await Testamento.findById(testamentoId);

        if (!testamento) {
            return res.status(404).json({
                success: false,
                error: 'Testamento no encontrado'
            });
        }

        const usuario = await Usuario.findById(testamento.usuario_id);

        res.json({
            success: true,
            testamento: {
                id: testamento.id,
                titulo: testamento.titulo,
                estado: testamento.estado,
                firmado: testamento.firma_digital !== null,
                firmado_en: testamento.firmado_en,
                created_at: testamento.created_at
            },
            autor: {
                username: usuario.username
            }
        });

    } catch (error) {
        logger.error('[VERIFICACION] Error:', error);
        res.status(500).json({
            success: false,
            error: 'Error al obtener información'
        });
    }
}

module.exports = {
    verificarFirma,
    obtenerInfo
};
