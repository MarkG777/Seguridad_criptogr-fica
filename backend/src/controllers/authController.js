/**
 * Controlador de Autenticación
 * CAPA 1: Login Seguro con bcrypt
 */

const authService = require('../security/AuthService');
const Usuario = require('../models/Usuario');
const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');

/**
 * Registrar nuevo usuario
 * POST /api/auth/register
 */
async function register(req, res) {
    try {
        const { username, email, password } = req.body;

        logger.info('[REGISTER] Intentando registrar usuario:', username);

        // Verificar si ya existe el username
        if (await Usuario.usernameExists(username)) {
            logger.warn('[REGISTER] Username ya existe:', username);
            return res.status(400).json({
                success: false,
                error: 'El username ya está en uso'
            });
        }

        // Verificar si ya existe el email
        if (await Usuario.emailExists(email)) {
            logger.warn('[REGISTER] Email ya existe:', email);
            return res.status(400).json({
                success: false,
                error: 'El email ya está registrado'
            });
        }

        // Validar fortaleza de contraseña
        const passwordValidation = authService.validatePasswordStrength(password);
        if (!passwordValidation.valid) {
            return res.status(400).json({
                success: false,
                error: 'Contraseña no cumple requisitos',
                errors: passwordValidation.errors
            });
        }

        // CAPA 1: Hashear contraseña con bcrypt
        logger.info('[REGISTER] Hasheando contraseña con bcrypt...');
        const password_hash = await authService.hashPassword(password);

        // CAPA 3: Generar par de llaves RSA para firma digital
        logger.info('[REGISTER] Generando par de llaves RSA para usuario...');
        const { publicKey, privateKey } = authService.generateUserKeyPair();

        // Crear usuario en la base de datos
        const usuario = await Usuario.create({
            username: authService.sanitizeUsername(username),
            email: email.toLowerCase(),
            password_hash: password_hash,
            public_key_pem: publicKey
        });

        logger.info('[REGISTER] Usuario creado exitosamente:', usuario.id);

        // Generar JWT token
        const token = authService.generateToken({
            userId: usuario.id,
            username: usuario.username
        });

        // Registrar en audit log
        await AuditLog.log({
            usuario_id: usuario.id,
            accion: 'registro',
            entidad: 'usuario',
            entidad_id: usuario.id,
            ip_address: req.clientIp,
            user_agent: req.userAgent,
            exitoso: true
        });

        // Responder con el token y la llave privada
        // IMPORTANTE: La llave privada se envía UNA SOLA VEZ
        // El usuario debe descargarla y guardarla de forma segura
        res.status(201).json({
            success: true,
            message: 'Usuario registrado exitosamente',
            token: token,
            user: {
                id: usuario.id,
                username: usuario.username,
                email: usuario.email
            },
            privateKey: privateKey, // Enviar una sola vez
            warning: 'IMPORTANTE: Guarda tu llave privada de forma segura. La necesitarás para firmar testamentos. No podrás recuperarla.'
        });

    } catch (error) {
        logger.error('[REGISTER] Error:', error);
        res.status(500).json({
            success: false,
            error: 'Error al registrar usuario'
        });
    }
}

/**
 * Login de usuario
 * POST /api/auth/login
 */
async function login(req, res) {
    try {
        const { username, password } = req.body;

        logger.info('[LOGIN] Intento de login:', username);

        // Buscar usuario
        const usuario = await Usuario.findByUsername(username);

        if (!usuario) {
            logger.warn('[LOGIN] Usuario no encontrado:', username);
            
            await AuditLog.logFailedLogin(
                username,
                req.clientIp,
                req.userAgent,
                'Usuario no existe'
            );

            return res.status(401).json({
                success: false,
                error: 'Credenciales inválidas'
            });
        }

        // CAPA 1: Verificar contraseña con bcrypt
        logger.info('[LOGIN] Verificando contraseña con bcrypt...');
        const passwordValid = await authService.verifyPassword(password, usuario.password_hash);

        if (!passwordValid) {
            logger.warn('[LOGIN] Contraseña incorrecta para:', username);
            
            await AuditLog.logFailedLogin(
                username,
                req.clientIp,
                req.userAgent,
                'Contraseña incorrecta'
            );

            return res.status(401).json({
                success: false,
                error: 'Credenciales inválidas'
            });
        }

        logger.info('[LOGIN] Login exitoso:', username);

        // Actualizar último login
        await Usuario.updateLastLogin(usuario.id);

        // Generar JWT token
        const token = authService.generateToken({
            userId: usuario.id,
            username: usuario.username
        });

        // Registrar en audit log
        await AuditLog.logLogin(usuario.id, req.clientIp, req.userAgent);

        res.json({
            success: true,
            message: 'Login exitoso',
            token: token,
            user: {
                id: usuario.id,
                username: usuario.username,
                email: usuario.email
            }
        });

    } catch (error) {
        logger.error('[LOGIN] Error:', error);
        res.status(500).json({
            success: false,
            error: 'Error al iniciar sesión'
        });
    }
}

/**
 * Obtener usuario actual
 * GET /api/auth/me
 */
async function getCurrentUser(req, res) {
    try {
        const usuario = await Usuario.findById(req.user.id);

        if (!usuario) {
            return res.status(404).json({
                success: false,
                error: 'Usuario no encontrado'
            });
        }

        res.json({
            success: true,
            user: {
                id: usuario.id,
                username: usuario.username,
                email: usuario.email,
                publicKey: usuario.public_key_pem,
                createdAt: usuario.created_at,
                lastLogin: usuario.last_login
            }
        });

    } catch (error) {
        logger.error('[ME] Error:', error);
        res.status(500).json({
            success: false,
            error: 'Error al obtener usuario'
        });
    }
}

/**
 * Logout
 * POST /api/auth/logout
 */
async function logout(req, res) {
    try {
        logger.info('[LOGOUT] Usuario:', req.user.username);

        await AuditLog.log({
            usuario_id: req.user.id,
            accion: 'logout',
            entidad: 'usuario',
            ip_address: req.clientIp,
            user_agent: req.userAgent,
            exitoso: true
        });

        res.json({
            success: true,
            message: 'Logout exitoso'
        });

    } catch (error) {
        logger.error('[LOGOUT] Error:', error);
        res.status(500).json({
            success: false,
            error: 'Error al cerrar sesión'
        });
    }
}

module.exports = {
    register,
    login,
    getCurrentUser,
    logout
};
