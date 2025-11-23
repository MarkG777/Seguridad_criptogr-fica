/**
 * Servidor Principal - Gestor de Testamentos Digitales
 * 4 Capas de Seguridad Criptográfica
 * 
 * @author Marco Antonio Gómez Olvera
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');

const database = require('./database/connection');
const logger = require('./utils/logger');
const { errorHandler } = require('./middleware/security');

// Importar rutas
const authRoutes = require('./routes/auth');
const testamentosRoutes = require('./routes/testamentos');
const verificacionRoutes = require('./routes/verificacion');
const cryptoRoutes = require('./routes/crypto');

// Crear aplicación Express
const app = express();
const PORT = process.env.PORT || 3000;

// ===== MIDDLEWARE DE SEGURIDAD =====

// Helmet - Headers de seguridad
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    frameguard: {
        action: 'deny'
    },
    noSniff: true,
    xssFilter: true
}));

// CORS
const allowedOrigins = process.env.ALLOWED_ORIGINS 
    ? process.env.ALLOWED_ORIGINS.split(',')
    : ['http://localhost:3000', 'http://127.0.0.1:3000'];

app.use(cors({
    origin: function(origin, callback) {
        // Permitir requests sin origin (como Postman)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('No permitido por CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Client-Public-Key']
}));

// Body parser
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

// Servir archivos estáticos (frontend)
app.use(express.static(path.join(__dirname, '../../frontend')));

// Logging de requests
app.use((req, res, next) => {
    logger.info(`${req.method} ${req.path}`, {
        ip: req.ip,
        userAgent: req.get('user-agent')
    });
    next();
});

// ===== RUTAS DE LA API =====

// Ruta raíz
app.get('/api', (req, res) => {
    res.json({
        success: true,
        message: 'API de Testamentos Digitales',
        version: '1.0.0',
        seguridad: {
            capa1: 'Login Seguro (bcrypt)',
            capa2: 'Cifrado Simétrico (AES-256)',
            capa3: 'Firma Digital (RSA-2048)',
            capa4: 'Cifrado Híbrido (RSA + AES-GCM)'
        },
        endpoints: {
            auth: '/api/auth',
            testamentos: '/api/testamentos',
            verificacion: '/api/verificar',
            crypto: '/api/crypto'
        }
    });
});

// Montar rutas
app.use('/api/auth', authRoutes);
app.use('/api/testamentos', testamentosRoutes);
app.use('/api/verificar', verificacionRoutes);
app.use('/api/crypto', cryptoRoutes);

// Ruta catch-all para el frontend
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../../frontend/index.html'));
});

// Manejo de errores 404
app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: 'Ruta no encontrada'
    });
});

// Manejo global de errores
app.use(errorHandler);

// ===== INICIALIZACIÓN =====

async function iniciarServidor() {
    try {
        console.log('\n==========================================================');
        console.log('  SISTEMA DE TESTAMENTOS DIGITALES');
        console.log('  4 Capas de Seguridad Criptográfica');
        console.log('==========================================================\n');

        // Conectar a base de datos
        console.log('[INIT] Conectando a base de datos...');
        await database.connect();
        console.log('[INIT] ✓ Base de datos conectada\n');

        // Verificar variables de entorno críticas
        console.log('[INIT] Verificando configuración de seguridad...');
        
        if (!process.env.JWT_SECRET) {
            throw new Error('JWT_SECRET no configurado');
        }
        console.log('[INIT] ✓ JWT_SECRET configurado');

        if (!process.env.DB_ENCRYPTION_KEY) {
            throw new Error('DB_ENCRYPTION_KEY no configurado');
        }
        console.log('[INIT] ✓ DB_ENCRYPTION_KEY configurado (AES-256)');

        // Verificar servicios de seguridad
        const encryptionService = require('./security/EncryptionService');
        if (!encryptionService.isConfigured()) {
            throw new Error('Encryption service no configurado correctamente');
        }
        console.log('[INIT] ✓ Encryption Service inicializado');

        const hybridCryptoService = require('./security/HybridCryptoService');
        console.log('[INIT] ✓ Hybrid Crypto Service inicializado');
        console.log('[INIT] ✓ Llaves RSA del servidor cargadas\n');

        // Iniciar servidor
        app.listen(PORT, () => {
            console.log('==========================================================');
            console.log(`  ✓ Servidor corriendo en http://localhost:${PORT}`);
            console.log('==========================================================\n');
            
            console.log('Endpoints disponibles:');
            console.log(`  • GET    http://localhost:${PORT}/api`);
            console.log(`  • POST   http://localhost:${PORT}/api/auth/register`);
            console.log(`  • POST   http://localhost:${PORT}/api/auth/login`);
            console.log(`  • GET    http://localhost:${PORT}/api/crypto/server-public-key`);
            console.log(`  • POST   http://localhost:${PORT}/api/testamentos/crear`);
            console.log(`  • GET    http://localhost:${PORT}/api/testamentos/mis-testamentos`);
            console.log(`  • POST   http://localhost:${PORT}/api/testamentos/:id/firmar`);
            console.log(`  • POST   http://localhost:${PORT}/api/verificar/firma`);
            console.log('\n4 Capas de Seguridad Activas:');
            console.log('  [1] Login Seguro - bcrypt para contraseñas');
            console.log('  [2] Cifrado Simétrico - AES-256-CBC para BD');
            console.log('  [3] Firma Digital - RSA-2048 para testamentos');
            console.log('  [4] Cifrado Híbrido - RSA + AES-GCM para comunicación');
            console.log('\n==========================================================\n');
            
            logger.info('Servidor iniciado exitosamente', {
                port: PORT,
                env: process.env.NODE_ENV || 'development'
            });
        });

    } catch (error) {
        console.error('\n[ERROR] Error al iniciar servidor:', error);
        logger.error('Error fatal al iniciar servidor', { error: error.message });
        process.exit(1);
    }
}

// Manejar cierre graceful
process.on('SIGTERM', async () => {
    console.log('\n[SHUTDOWN] Recibida señal SIGTERM, cerrando servidor...');
    await database.close();
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('\n[SHUTDOWN] Recibida señal SIGINT, cerrando servidor...');
    await database.close();
    process.exit(0);
});

// Iniciar servidor
iniciarServidor();

module.exports = app;
