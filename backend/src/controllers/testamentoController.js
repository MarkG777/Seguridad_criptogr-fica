/**
 * Controlador de Testamentos
 * Integra las 4 capas de seguridad
 */

const hybridCryptoService = require('../security/HybridCryptoService');
const encryptionService = require('../security/EncryptionService');
const signatureService = require('../security/SignatureService');
const Testamento = require('../models/Testamento');
const Usuario = require('../models/Usuario');
const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');

/**
 * Crear nuevo testamento
 * POST /api/testamentos/crear
 * 
 * CAPA 4: Recibe datos con cifrado híbrido
 * CAPA 2: Guarda datos cifrados con AES-256 en BD
 */
async function crear(req, res) {
    try {
        logger.info('[TESTAMENTO] Creando testamento para usuario:', req.user.id);

        // CAPA 4: Descifrar sobre digital
        logger.info('[TESTAMENTO] Descifrando sobre digital...');
        const resultado = hybridCryptoService.decryptDigitalEnvelope(req.body);

        if (!resultado.success) {
            logger.error('[TESTAMENTO] Error al descifrar sobre digital');
            return res.status(400).json({
                success: false,
                error: 'Error al descifrar datos'
            });
        }

        const { contenido, cuentas_bancarias, beneficiarios, titulo } = resultado.data;

        logger.info('[TESTAMENTO] Datos descifrados correctamente');
        logger.info('[TESTAMENTO] Contenido length:', contenido.length);
        logger.info('[TESTAMENTO] Cuentas bancarias:', cuentas_bancarias?.length || 0);

        // CAPA 2: Cifrar contenido para la base de datos
        logger.info('[TESTAMENTO] Cifrando contenido con AES-256 para BD...');
        const contenidoCifrado = encryptionService.encryptTestamentContent(contenido);

        // CAPA 2: Cifrar cuentas bancarias si existen
        let cuentasCifradas = null;
        let ivCuentas = null;
        
        if (cuentas_bancarias && cuentas_bancarias.length > 0) {
            logger.info('[TESTAMENTO] Cifrando cuentas bancarias con AES-256...');
            const resultado = encryptionService.encryptBankAccounts(cuentas_bancarias);
            cuentasCifradas = resultado.encrypted;
            ivCuentas = resultado.iv;
        }

        // Guardar en base de datos
        const testamentoId = await Testamento.create({
            usuario_id: req.user.id,
            contenido_cifrado: contenidoCifrado.encrypted,
            iv_contenido: contenidoCifrado.iv,
            cuentas_bancarias_cifradas: cuentasCifradas,
            iv_cuentas: ivCuentas,
            titulo: titulo || 'Mi Testamento'
        });

        logger.info('[TESTAMENTO] Testamento creado con ID:', testamentoId);

        // Registrar en audit log
        await AuditLog.logTestamentCreated(req.user.id, testamentoId, req.clientIp);

        // CAPA 4: Cifrar respuesta para el cliente
        const publicKeyCliente = req.headers['x-client-public-key'];
        
        let respuesta = {
            success: true,
            message: 'Testamento creado exitosamente',
            testamentoId: testamentoId
        };

        // Si el cliente envió su llave pública, cifrar respuesta
        if (publicKeyCliente) {
            const resultadoCifrado = hybridCryptoService.encryptDigitalEnvelope(
                respuesta,
                publicKeyCliente
            );
            
            if (resultadoCifrado.success) {
                return res.json({
                    success: true,
                    encrypted: true,
                    ...resultadoCifrado.envelope
                });
            }
        }

        // Si no hay llave pública del cliente, enviar sin cifrar
        res.json(respuesta);

    } catch (error) {
        logger.error('[TESTAMENTO] Error al crear:', error);
        res.status(500).json({
            success: false,
            error: 'Error al crear testamento'
        });
    }
}

/**
 * Obtener testamento por ID
 * GET /api/testamentos/:id
 * 
 * CAPA 2: Descifra datos de BD
 * CAPA 4: Envía con cifrado híbrido
 */
async function obtener(req, res) {
    try {
        const testamentoId = req.params.id;
        
        logger.info('[TESTAMENTO] Obteniendo testamento:', testamentoId);

        // Verificar propiedad
        const esPropio = await Testamento.verifyOwnership(testamentoId, req.user.id);
        
        if (!esPropio) {
            logger.warn('[TESTAMENTO] Usuario no autorizado:', req.user.id);
            return res.status(403).json({
                success: false,
                error: 'No autorizado'
            });
        }

        // Obtener testamento
        const testamento = await Testamento.findById(testamentoId);

        if (!testamento) {
            return res.status(404).json({
                success: false,
                error: 'Testamento no encontrado'
            });
        }

        // CAPA 2: Descifrar contenido de BD
        logger.info('[TESTAMENTO] Descifrando contenido de BD con AES-256...');
        const contenido = encryptionService.decryptTestamentContent(
            testamento.contenido_cifrado,
            testamento.iv_contenido
        );

        // Descifrar cuentas bancarias si existen
        let cuentas_bancarias = null;
        if (testamento.cuentas_bancarias_cifradas) {
            logger.info('[TESTAMENTO] Descifrando cuentas bancarias...');
            cuentas_bancarias = encryptionService.decryptBankAccounts(
                testamento.cuentas_bancarias_cifradas,
                testamento.iv_cuentas
            );
        }

        // Registrar acceso en audit log
        await AuditLog.logTestamentAccessed(req.user.id, testamentoId, req.clientIp);

        // Preparar respuesta
        const respuesta = {
            success: true,
            testamento: {
                id: testamento.id,
                titulo: testamento.titulo,
                contenido: contenido,
                cuentas_bancarias: cuentas_bancarias,
                estado: testamento.estado,
                firmado: testamento.firma_digital !== null,
                firmado_en: testamento.firmado_en,
                created_at: testamento.created_at,
                updated_at: testamento.updated_at
            }
        };

        // CAPA 4: Cifrar respuesta si el cliente envió su llave pública
        const publicKeyCliente = req.headers['x-client-public-key'];
        
        if (publicKeyCliente) {
            const resultadoCifrado = hybridCryptoService.encryptDigitalEnvelope(
                respuesta,
                publicKeyCliente
            );
            
            if (resultadoCifrado.success) {
                return res.json({
                    success: true,
                    encrypted: true,
                    ...resultadoCifrado.envelope
                });
            }
        }

        res.json(respuesta);

    } catch (error) {
        logger.error('[TESTAMENTO] Error al obtener:', error);
        res.status(500).json({
            success: false,
            error: 'Error al obtener testamento'
        });
    }
}

/**
 * Listar testamentos del usuario
 * GET /api/testamentos/mis-testamentos
 */
async function listar(req, res) {
    try {
        logger.info('[TESTAMENTO] Listando testamentos de usuario:', req.user.id);

        const testamentos = await Testamento.findByUserId(req.user.id);
        const stats = await Testamento.countByUserId(req.user.id);

        res.json({
            success: true,
            testamentos: testamentos,
            stats: stats
        });

    } catch (error) {
        logger.error('[TESTAMENTO] Error al listar:', error);
        res.status(500).json({
            success: false,
            error: 'Error al listar testamentos'
        });
    }
}

/**
 * Actualizar testamento
 * PUT /api/testamentos/:id
 * 
 * Solo se pueden actualizar borradores (no firmados)
 */
async function actualizar(req, res) {
    try {
        const testamentoId = req.params.id;
        
        logger.info('[TESTAMENTO] Actualizando testamento:', testamentoId);

        // Verificar propiedad
        const esPropio = await Testamento.verifyOwnership(testamentoId, req.user.id);
        
        if (!esPropio) {
            return res.status(403).json({
                success: false,
                error: 'No autorizado'
            });
        }

        // Verificar que sea borrador
        const testamento = await Testamento.findById(testamentoId);
        
        if (testamento.estado !== 'borrador') {
            return res.status(400).json({
                success: false,
                error: 'No se puede modificar un testamento firmado'
            });
        }

        // CAPA 4: Descifrar sobre digital
        const resultado = hybridCryptoService.decryptDigitalEnvelope(req.body);

        if (!resultado.success) {
            return res.status(400).json({
                success: false,
                error: 'Error al descifrar datos'
            });
        }

        const { contenido, cuentas_bancarias, titulo } = resultado.data;

        // CAPA 2: Cifrar nuevo contenido
        const contenidoCifrado = encryptionService.encryptTestamentContent(contenido);

        let cuentasCifradas = null;
        let ivCuentas = null;
        
        if (cuentas_bancarias && cuentas_bancarias.length > 0) {
            const resultado = encryptionService.encryptBankAccounts(cuentas_bancarias);
            cuentasCifradas = resultado.encrypted;
            ivCuentas = resultado.iv;
        }

        // Actualizar en BD
        const actualizado = await Testamento.update(testamentoId, {
            contenido_cifrado: contenidoCifrado.encrypted,
            iv_contenido: contenidoCifrado.iv,
            cuentas_bancarias_cifradas: cuentasCifradas,
            iv_cuentas: ivCuentas,
            titulo: titulo
        });

        if (!actualizado) {
            return res.status(400).json({
                success: false,
                error: 'No se pudo actualizar el testamento'
            });
        }

        logger.info('[TESTAMENTO] Testamento actualizado:', testamentoId);

        await AuditLog.log({
            usuario_id: req.user.id,
            accion: 'testamento_actualizado',
            entidad: 'testamento',
            entidad_id: testamentoId,
            ip_address: req.clientIp,
            exitoso: true
        });

        res.json({
            success: true,
            message: 'Testamento actualizado exitosamente'
        });

    } catch (error) {
        logger.error('[TESTAMENTO] Error al actualizar:', error);
        res.status(500).json({
            success: false,
            error: 'Error al actualizar testamento'
        });
    }
}

/**
 * Firmar testamento
 * POST /api/testamentos/:id/firmar
 * 
 * CAPA 3: Firma digital con RSA
 * CAPA 4: Recibe firma con cifrado híbrido
 */
async function firmar(req, res) {
    try {
        const testamentoId = req.params.id;
        
        logger.info('[TESTAMENTO] Firmando testamento:', testamentoId);

        // Verificar propiedad
        const esPropio = await Testamento.verifyOwnership(testamentoId, req.user.id);
        
        if (!esPropio) {
            return res.status(403).json({
                success: false,
                error: 'No autorizado'
            });
        }

        // Verificar que sea borrador
        const testamento = await Testamento.findById(testamentoId);
        
        if (testamento.estado !== 'borrador') {
            return res.status(400).json({
                success: false,
                error: 'El testamento ya está firmado'
            });
        }

        // CAPA 4: Descifrar sobre digital
        const resultado = hybridCryptoService.decryptDigitalEnvelope(req.body);

        if (!resultado.success) {
            return res.status(400).json({
                success: false,
                error: 'Error al descifrar datos'
            });
        }

        const { firma_digital, hash_original } = resultado.data;

        logger.info('[TESTAMENTO] Datos de firma recibidos');

        // Descifrar contenido original del testamento para verificar
        const contenidoOriginal = encryptionService.decryptTestamentContent(
            testamento.contenido_cifrado,
            testamento.iv_contenido
        );

        // CAPA 3: Verificar firma digital
        logger.info('[TESTAMENTO] Verificando firma digital con RSA...');
        
        const firmaValida = signatureService.verifySignature(
            contenidoOriginal,
            firma_digital,
            req.user.publicKey,
            hash_original
        );

        if (!firmaValida) {
            logger.error('[TESTAMENTO] Firma inválida');
            return res.status(400).json({
                success: false,
                error: 'Firma digital inválida'
            });
        }

        logger.info('[TESTAMENTO] Firma verificada correctamente');

        // Guardar firma en BD
        const firmado = await Testamento.sign(testamentoId, {
            firma_digital: firma_digital,
            hash_original: hash_original
        });

        if (!firmado) {
            return res.status(400).json({
                success: false,
                error: 'No se pudo firmar el testamento'
            });
        }

        logger.info('[TESTAMENTO] Testamento firmado exitosamente:', testamentoId);

        // Registrar en audit log
        await AuditLog.logTestamentSigned(req.user.id, testamentoId, req.clientIp);

        res.json({
            success: true,
            message: 'Testamento firmado exitosamente',
            verificado: true
        });

    } catch (error) {
        logger.error('[TESTAMENTO] Error al firmar:', error);
        res.status(500).json({
            success: false,
            error: 'Error al firmar testamento'
        });
    }
}

/**
 * Eliminar testamento
 * DELETE /api/testamentos/:id
 * 
 * Solo se pueden eliminar borradores
 */
async function eliminar(req, res) {
    try {
        const testamentoId = req.params.id;
        
        logger.info('[TESTAMENTO] Eliminando testamento:', testamentoId);

        // Verificar propiedad
        const esPropio = await Testamento.verifyOwnership(testamentoId, req.user.id);
        
        if (!esPropio) {
            return res.status(403).json({
                success: false,
                error: 'No autorizado'
            });
        }

        // Eliminar (solo si es borrador)
        const eliminado = await Testamento.delete(testamentoId);

        if (!eliminado) {
            return res.status(400).json({
                success: false,
                error: 'No se puede eliminar un testamento firmado'
            });
        }

        logger.info('[TESTAMENTO] Testamento eliminado:', testamentoId);

        await AuditLog.log({
            usuario_id: req.user.id,
            accion: 'testamento_eliminado',
            entidad: 'testamento',
            entidad_id: testamentoId,
            ip_address: req.clientIp,
            exitoso: true
        });

        res.json({
            success: true,
            message: 'Testamento eliminado exitosamente'
        });

    } catch (error) {
        logger.error('[TESTAMENTO] Error al eliminar:', error);
        res.status(500).json({
            success: false,
            error: 'Error al eliminar testamento'
        });
    }
}

module.exports = {
    crear,
    obtener,
    listar,
    actualizar,
    firmar,
    eliminar
};
