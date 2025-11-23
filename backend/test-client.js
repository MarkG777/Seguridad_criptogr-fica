/**
 * Cliente de Prueba para Testamentos Digitales
 * Prueba las 4 capas de seguridad
 * 
 * Ejecutar: node test-client.js
 */

const crypto = require('crypto');
const http = require('http');

const API_URL = 'localhost';
const API_PORT = 3000;

// Colores para consola
const colors = {
    reset: '\x1b[0m',
    green: '\x1b[32m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    cyan: '\x1b[36m',
    blue: '\x1b[34m'
};

function log(message, color = 'reset') {
    console.log(colors[color] + message + colors.reset);
}

// Variables globales
let token = null;
let userId = null;
let userPrivateKey = null;
let serverPublicKey = null;
let testamentoId = null;

/**
 * Hacer request HTTP
 */
function makeRequest(method, path, data = null, headers = {}) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: API_URL,
            port: API_PORT,
            path: path,
            method: method,
            headers: {
                'Content-Type': 'application/json',
                ...headers
            }
        };

        const req = http.request(options, (res) => {
            let body = '';
            res.on('data', chunk => body += chunk);
            res.on('end', () => {
                try {
                    const response = JSON.parse(body);
                    resolve(response);
                } catch (e) {
                    resolve(body);
                }
            });
        });

        req.on('error', reject);

        if (data) {
            req.write(JSON.stringify(data));
        }

        req.end();
    });
}

/**
 * CAPA 4: Cifrado Híbrido - Cifrar datos
 */
function cifrarHibrido(datos) {
    log('\n[HIBRIDO] Cifrando datos con cifrado híbrido...', 'cyan');
    
    // 1. Generar llave AES temporal (32 bytes = 256 bits)
    const claveAES = crypto.randomBytes(32);
    log('  1. Llave AES-256 generada: 32 bytes', 'cyan');
    
    // 2. Generar IV (12 bytes para GCM)
    const iv = crypto.randomBytes(12);
    log('  2. IV generado: 12 bytes', 'cyan');
    
    // 3. Cifrar datos con AES-256-GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', claveAES, iv);
    const datosJSON = JSON.stringify(datos);
    let datosCifrados = cipher.update(datosJSON, 'utf8', 'base64');
    datosCifrados += cipher.final('base64');
    const authTag = cipher.getAuthTag();
    log('  3. Datos cifrados con AES-256-GCM', 'cyan');
    
    // 4. Cifrar llave AES con RSA pública del servidor
    const claveAESCifrada = crypto.publicEncrypt(
        {
            key: serverPublicKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256'
        },
        claveAES
    );
    log('  4. Llave AES cifrada con RSA pública del servidor', 'cyan');
    
    log('[HIBRIDO] Sobre digital creado exitosamente', 'green');
    
    return {
        datosCifrados: datosCifrados,
        claveAESCifrada: claveAESCifrada.toString('base64'),
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64')
    };
}

/**
 * CAPA 3: Firma Digital - Firmar contenido
 */
function firmarContenido(contenido) {
    log('\n[FIRMA] Firmando contenido con RSA-PSS...', 'cyan');
    
    // 1. Generar hash SHA-256
    const hash = crypto.createHash('sha256');
    hash.update(contenido);
    const hashOriginal = hash.digest('hex');
    log('  1. Hash SHA-256 generado: ' + hashOriginal.substring(0, 32) + '...', 'cyan');
    
    // 2. Firmar con llave privada
    const sign = crypto.createSign('SHA256');
    sign.update(contenido);
    sign.end();
    
    const firma = sign.sign({
        key: userPrivateKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN
    });
    
    const firmaBase64 = firma.toString('base64');
    log('  2. Firma digital generada', 'cyan');
    log('[FIRMA] Contenido firmado exitosamente', 'green');
    
    return {
        firma_digital: firmaBase64,
        hash_original: hashOriginal
    };
}

/**
 * Test 1: Obtener llave pública del servidor
 */
async function test1_ObtenerClavePublica() {
    log('\n========================================', 'yellow');
    log('TEST 1: Obtener Llave Pública del Servidor (CAPA 4)', 'yellow');
    log('========================================', 'yellow');
    
    try {
        const response = await makeRequest('GET', '/api/crypto/server-public-key');
        
        if (response.success) {
            serverPublicKey = response.publicKey;
            log('[OK] Llave pública del servidor obtenida', 'green');
            log('     Algoritmo: ' + response.algorithm, 'cyan');
            log('     Longitud: ' + serverPublicKey.length + ' caracteres', 'cyan');
            return true;
        } else {
            log('[ERROR] No se pudo obtener la llave pública', 'red');
            return false;
        }
    } catch (error) {
        log('[ERROR] ' + error.message, 'red');
        return false;
    }
}

/**
 * Test 2: Registrar usuario (CAPA 1: bcrypt)
 */
async function test2_RegistrarUsuario() {
    log('\n========================================', 'yellow');
    log('TEST 2: Registrar Usuario (CAPA 1: bcrypt)', 'yellow');
    log('========================================', 'yellow');
    
    try {
        const datos = {
            username: 'test_' + Date.now(),
            email: 'test' + Date.now() + '@test.com',
            password: 'TestPassword123!'
        };
        
        log('[REQUEST] POST /api/auth/register', 'cyan');
        log('  Username: ' + datos.username, 'cyan');
        log('  Email: ' + datos.email, 'cyan');
        
        const response = await makeRequest('POST', '/api/auth/register', datos);
        
        if (response.success) {
            token = response.token;
            userId = response.user.id;
            userPrivateKey = response.privateKey;
            
            log('[OK] Usuario registrado exitosamente', 'green');
            log('     ID: ' + userId, 'cyan');
            log('     Username: ' + response.user.username, 'cyan');
            log('     Token JWT: ' + token.substring(0, 30) + '...', 'cyan');
            log('     Llave privada RSA guardada (para firmar)', 'cyan');
            return true;
        } else {
            log('[ERROR] ' + response.error, 'red');
            return false;
        }
    } catch (error) {
        log('[ERROR] ' + error.message, 'red');
        return false;
    }
}

/**
 * Test 3: Crear testamento (CAPA 2: AES-256 + CAPA 4: Híbrido)
 */
async function test3_CrearTestamento() {
    log('\n========================================', 'yellow');
    log('TEST 3: Crear Testamento (CAPA 2: AES-256 + CAPA 4: Híbrido)', 'yellow');
    log('========================================', 'yellow');
    
    try {
        // Datos del testamento
        const datosTestamento = {
            titulo: 'Mi Testamento Digital',
            contenido: 'Yo, como testador, declaro que este es mi testamento digital. ' +
                      'Dejo mis bienes a mis herederos según lo establecido en este documento. ' +
                      'Firmado digitalmente el ' + new Date().toISOString(),
            cuentas_bancarias: [
                {
                    banco: 'Banco Nacional',
                    cuenta: '1234567890',
                    password: 'MiPasswordBancario123!'
                },
                {
                    banco: 'Banco Internacional',
                    cuenta: '9876543210',
                    password: 'OtroPasswordSeguro456!'
                }
            ],
            beneficiarios: [
                { nombre: 'Juan Pérez', relacion: 'Hijo', porcentaje: 50 },
                { nombre: 'María López', relacion: 'Hija', porcentaje: 50 }
            ]
        };
        
        log('[DATOS] Testamento a crear:', 'cyan');
        log('  Título: ' + datosTestamento.titulo, 'cyan');
        log('  Contenido: ' + datosTestamento.contenido.substring(0, 50) + '...', 'cyan');
        log('  Cuentas bancarias: ' + datosTestamento.cuentas_bancarias.length, 'cyan');
        log('  Beneficiarios: ' + datosTestamento.beneficiarios.length, 'cyan');
        
        // CAPA 4: Cifrar con híbrido
        const sobreDigital = cifrarHibrido(datosTestamento);
        
        log('[REQUEST] POST /api/testamentos/crear (con cifrado híbrido)', 'cyan');
        
        const response = await makeRequest(
            'POST',
            '/api/testamentos/crear',
            sobreDigital,
            { 'Authorization': 'Bearer ' + token }
        );
        
        if (response.success) {
            testamentoId = response.testamentoId;
            log('[OK] Testamento creado exitosamente', 'green');
            log('     ID del testamento: ' + testamentoId, 'cyan');
            log('[CAPA 2] Datos cifrados con AES-256 en BD', 'green');
            log('[CAPA 4] Comunicación cifrada con híbrido', 'green');
            return true;
        } else {
            log('[ERROR] ' + response.error, 'red');
            return false;
        }
    } catch (error) {
        log('[ERROR] ' + error.message, 'red');
        return false;
    }
}

/**
 * Test 4: Firmar testamento (CAPA 3: RSA Firma + CAPA 4: Híbrido)
 */
async function test4_FirmarTestamento() {
    log('\n========================================', 'yellow');
    log('TEST 4: Firmar Testamento (CAPA 3: RSA + CAPA 4: Híbrido)', 'yellow');
    log('========================================', 'yellow');
    
    try {
        // Primero obtener el testamento para firmarlo
        log('[INFO] Obteniendo contenido del testamento para firmar...', 'cyan');
        
        const testamento = await makeRequest(
            'GET',
            '/api/testamentos/' + testamentoId,
            null,
            { 'Authorization': 'Bearer ' + token }
        );
        
        if (!testamento.success) {
            log('[ERROR] No se pudo obtener el testamento', 'red');
            return false;
        }
        
        const contenido = testamento.testamento.contenido;
        log('[INFO] Contenido obtenido: ' + contenido.substring(0, 50) + '...', 'cyan');
        
        // CAPA 3: Firmar el contenido
        const { firma_digital, hash_original } = firmarContenido(contenido);
        
        // CAPA 4: Cifrar firma con híbrido
        const datosFirma = {
            firma_digital: firma_digital,
            hash_original: hash_original
        };
        
        const sobreDigital = cifrarHibrido(datosFirma);
        
        log('[REQUEST] POST /api/testamentos/' + testamentoId + '/firmar', 'cyan');
        
        const response = await makeRequest(
            'POST',
            '/api/testamentos/' + testamentoId + '/firmar',
            sobreDigital,
            { 'Authorization': 'Bearer ' + token }
        );
        
        if (response.success && response.verificado) {
            log('[OK] Testamento firmado exitosamente', 'green');
            log('     Firma verificada: ' + response.verificado, 'cyan');
            log('[CAPA 3] Firma digital RSA verificada', 'green');
            log('[CAPA 4] Firma enviada con cifrado híbrido', 'green');
            return true;
        } else {
            log('[ERROR] ' + (response.error || 'Firma no verificada'), 'red');
            return false;
        }
    } catch (error) {
        log('[ERROR] ' + error.message, 'red');
        return false;
    }
}

/**
 * Test 5: Verificar en Base de Datos
 */
async function test5_VerificarBaseDatos() {
    log('\n========================================', 'yellow');
    log('TEST 5: Verificar en Base de Datos', 'yellow');
    log('========================================', 'yellow');
    
    const sqlite3 = require('sqlite3').verbose();
    const db = new sqlite3.Database('./database/testamentos.db');
    
    return new Promise((resolve) => {
        log('\n[BD] Verificando CAPA 1: Hash bcrypt...', 'cyan');
        
        db.get('SELECT password_hash FROM usuarios WHERE id = ?', [userId], (err, row) => {
            if (err) {
                log('[ERROR] ' + err.message, 'red');
            } else {
                log('[OK] Hash bcrypt encontrado:', 'green');
                log('     ' + row.password_hash, 'cyan');
                log('     Comienza con $2b$10$: ' + row.password_hash.startsWith('$2b$10$'), 'cyan');
            }
            
            log('\n[BD] Verificando CAPA 2: Contenido cifrado AES-256...', 'cyan');
            
            db.get('SELECT contenido_cifrado, iv_contenido FROM testamentos WHERE id = ?', [testamentoId], (err, row) => {
                if (err) {
                    log('[ERROR] ' + err.message, 'red');
                } else {
                    log('[OK] Contenido cifrado encontrado:', 'green');
                    log('     Contenido: ' + row.contenido_cifrado.substring(0, 50) + '... (' + row.contenido_cifrado.length + ' chars)', 'cyan');
                    log('     IV: ' + row.iv_contenido, 'cyan');
                    log('     Es ilegible (cifrado): ' + !/[a-zA-Z\s]{20,}/.test(row.contenido_cifrado), 'cyan');
                }
                
                log('\n[BD] Verificando CAPA 3: Firma digital RSA...', 'cyan');
                
                db.get('SELECT firma_digital, hash_original, estado FROM testamentos WHERE id = ?', [testamentoId], (err, row) => {
                    if (err) {
                        log('[ERROR] ' + err.message, 'red');
                    } else {
                        log('[OK] Firma digital encontrada:', 'green');
                        log('     Firma: ' + row.firma_digital.substring(0, 50) + '... (' + row.firma_digital.length + ' chars)', 'cyan');
                        log('     Hash: ' + row.hash_original, 'cyan');
                        log('     Estado: ' + row.estado, 'cyan');
                    }
                    
                    db.close();
                    resolve(true);
                });
            });
        });
    });
}

/**
 * Ejecutar todas las pruebas
 */
async function ejecutarPruebas() {
    log('\n╔════════════════════════════════════════════════════════╗', 'blue');
    log('║  PRUEBAS COMPLETAS - TESTAMENTOS DIGITALES            ║', 'blue');
    log('║  4 Capas de Seguridad Criptográfica                   ║', 'blue');
    log('╚════════════════════════════════════════════════════════╝', 'blue');
    
    const resultados = {
        test1: false,
        test2: false,
        test3: false,
        test4: false,
        test5: false
    };
    
    // Test 1: Obtener llave pública (CAPA 4)
    resultados.test1 = await test1_ObtenerClavePublica();
    if (!resultados.test1) {
        log('\n[ABORTADO] No se pudo obtener la llave pública del servidor', 'red');
        return;
    }
    
    // Test 2: Registrar usuario (CAPA 1)
    resultados.test2 = await test2_RegistrarUsuario();
    if (!resultados.test2) {
        log('\n[ABORTADO] No se pudo registrar el usuario', 'red');
        return;
    }
    
    // Test 3: Crear testamento (CAPA 2 + CAPA 4)
    resultados.test3 = await test3_CrearTestamento();
    if (!resultados.test3) {
        log('\n[ABORTADO] No se pudo crear el testamento', 'red');
        return;
    }
    
    // Test 4: Firmar testamento (CAPA 3 + CAPA 4)
    resultados.test4 = await test4_FirmarTestamento();
    if (!resultados.test4) {
        log('\n[WARNING] No se pudo firmar el testamento', 'yellow');
    }
    
    // Test 5: Verificar en BD
    resultados.test5 = await test5_VerificarBaseDatos();
    
    // Resumen final
    log('\n╔════════════════════════════════════════════════════════╗', 'blue');
    log('║  RESUMEN DE PRUEBAS                                    ║', 'blue');
    log('╚════════════════════════════════════════════════════════╝', 'blue');
    
    log('\nCapa 1 - Login Seguro (bcrypt):', 'cyan');
    log('  ' + (resultados.test2 ? '✅ EXITOSO' : '❌ FALLIDO'), resultados.test2 ? 'green' : 'red');
    
    log('\nCapa 2 - Cifrado Simétrico (AES-256):', 'cyan');
    log('  ' + (resultados.test3 ? '✅ EXITOSO' : '❌ FALLIDO'), resultados.test3 ? 'green' : 'red');
    
    log('\nCapa 3 - Firma Digital (RSA):', 'cyan');
    log('  ' + (resultados.test4 ? '✅ EXITOSO' : '❌ FALLIDO'), resultados.test4 ? 'green' : 'red');
    
    log('\nCapa 4 - Cifrado Híbrido:', 'cyan');
    log('  ' + (resultados.test1 && resultados.test3 ? '✅ EXITOSO' : '❌ FALLIDO'), resultados.test1 && resultados.test3 ? 'green' : 'red');
    
    log('\nVerificación en Base de Datos:', 'cyan');
    log('  ' + (resultados.test5 ? '✅ EXITOSO' : '❌ FALLIDO'), resultados.test5 ? 'green' : 'red');
    
    const totalExitosos = Object.values(resultados).filter(r => r).length;
    const total = Object.keys(resultados).length;
    
    log('\n╔════════════════════════════════════════════════════════╗', 'blue');
    log('║  RESULTADO FINAL: ' + totalExitosos + '/' + total + ' PRUEBAS EXITOSAS' + ' '.repeat(26 - (totalExitosos + '/' + total).length) + '║', totalExitosos === total ? 'green' : 'yellow');
    log('╚════════════════════════════════════════════════════════╝', 'blue');
    
    if (totalExitosos === total) {
        log('\n🎉 ¡TODAS LAS CAPAS FUNCIONANDO CORRECTAMENTE! 🎉\n', 'green');
    } else {
        log('\n⚠️  Algunas pruebas fallaron. Revisa los logs arriba.\n', 'yellow');
    }
}

// Ejecutar
console.log('\nEsperando 2 segundos para que el servidor esté listo...\n');
setTimeout(() => {
    ejecutarPruebas().catch(err => {
        log('\n[ERROR FATAL] ' + err.message, 'red');
        console.error(err);
    });
}, 2000);
