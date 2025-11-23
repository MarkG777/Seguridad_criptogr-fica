# Arquitectura del Sistema - Gestor de Testamentos Digitales

**Alumno:** Marco Antonio Gómez Olvera  
**Materia:** Seguridad Informática  
**Profesor:** Brandon Efren Venegas Olvera  
**Institución:** UTEQ  
**Fecha:** Noviembre 2025

---

## 1. Descripción General

Sistema de gestión de testamentos digitales con 4 capas de seguridad criptográfica que garantiza la confidencialidad, integridad, autenticidad y no repudio de la información testamentaria.

---

## 2. Stack Tecnológico

### Backend
- **Node.js** v16+
- **Express.js** - Framework web
- **SQLite3** - Base de datos (archivo local)
- **bcrypt** - Hash de contraseñas
- **crypto (nativo)** - Cifrado AES-256, RSA, SHA-256
- **jsonwebtoken** - Tokens de sesión
- **express-validator** - Validación de datos
- **helmet** - Headers de seguridad
- **winston** - Logging

### Frontend
- **HTML5** - Estructura
- **CSS3** - Estilos
- **JavaScript (Vanilla)** - Lógica
- **Web Crypto API** - Cifrado en el cliente

---

## 3. Arquitectura de Seguridad (4 Capas)

```
┌─────────────────────────────────────────────────────────────┐
│                         CLIENTE (Navegador)                  │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ CAPA 1: LOGIN SEGURO                                   │ │
│  │ - Formulario de registro/login                         │ │
│  │ - Envío de contraseña (se hasheará en servidor)       │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ CAPA 3: FIRMA DIGITAL                                  │ │
│  │ - Generación de par de llaves RSA (usuario)           │ │
│  │ - Firma del testamento con llave privada              │ │
│  │ - Hash SHA-256 del contenido                          │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ CAPA 4: CIFRADO HÍBRIDO (Sobre Digital)               │ │
│  │ - Generar llave AES temporal                          │ │
│  │ - Cifrar datos con AES-256-GCM                        │ │
│  │ - Cifrar llave AES con RSA pública del servidor       │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
└────────────────────┬─────────────────────────────────────────┘
                     │
                     │  HTTPS + Cifrado Híbrido
                     │  (Defense in Depth)
                     ↓
┌─────────────────────────────────────────────────────────────┐
│                         SERVIDOR (Node.js)                   │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ CAPA 4: DESCIFRADO HÍBRIDO                             │ │
│  │ - Descifrar llave AES con RSA privada del servidor    │ │
│  │ - Descifrar datos con AES-256-GCM                     │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ CAPA 1: AUTENTICACIÓN                                  │ │
│  │ - Verificación bcrypt de contraseña                   │ │
│  │ - Generación de JWT token                             │ │
│  │ - Middleware de autenticación                         │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ CAPA 3: VERIFICACIÓN DE FIRMA                          │ │
│  │ - Validar firma con llave pública del usuario         │ │
│  │ - Verificar integridad del testamento                 │ │
│  │ - Garantizar no repudio                               │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ CAPA 2: CIFRADO SIMÉTRICO (Base de Datos)             │ │
│  │ - Cifrar contenido de testamento con AES-256          │ │
│  │ - Cifrar claves de cuentas bancarias                  │ │
│  │ - Gestión segura de Key + IV                          │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
└────────────────────┬─────────────────────────────────────────┘
                     │
                     ↓
┌─────────────────────────────────────────────────────────────┐
│                     BASE DE DATOS (SQLite)                   │
│                                                              │
│  Tabla: usuarios                                            │
│  - id                                                        │
│  - username                                                  │
│  - email                                                     │
│  - password_hash (bcrypt)                                   │
│  - public_key_pem                                           │
│  - created_at                                               │
│                                                              │
│  Tabla: testamentos                                         │
│  - id                                                        │
│  - usuario_id (FK)                                          │
│  - contenido_cifrado (AES-256)                             │
│  - cuentas_bancarias_cifradas (AES-256)                    │
│  - iv_contenido (Vector Inicialización)                    │
│  - iv_cuentas (Vector Inicialización)                      │
│  - firma_digital (RSA signature)                            │
│  - hash_original (SHA-256)                                  │
│  - firmado_en (timestamp)                                   │
│  - estado (draft/firmado/ejecutado)                        │
│  - created_at                                               │
│  - updated_at                                               │
│                                                              │
│  Tabla: beneficiarios                                       │
│  - id                                                        │
│  - testamento_id (FK)                                       │
│  - nombre_cifrado                                           │
│  - relacion_cifrada                                         │
│  - porcentaje                                               │
│  - iv                                                        │
│                                                              │
│  Tabla: audit_log                                           │
│  - id                                                        │
│  - usuario_id                                               │
│  - accion                                                    │
│  - timestamp                                                │
│  - ip_address                                               │
│  - detalles                                                 │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Flujo de Datos Detallado

### 4.1. Registro de Usuario

```
1. Cliente: Formulario con username, email, password
2. Servidor: 
   a. Validar datos
   b. Generar hash bcrypt de la contraseña
   c. Generar par de llaves RSA para el usuario
   d. Guardar en BD: user, email, password_hash, public_key_pem
   e. Retornar: success + JWT token
3. Cliente: Guardar token en localStorage
```

### 4.2. Login de Usuario

```
1. Cliente: Enviar username + password
2. Servidor:
   a. Buscar usuario en BD
   b. Comparar password con bcrypt.compare()
   c. Si válido: generar JWT token
   d. Retornar: success + token + user_info
3. Cliente: Guardar token, redirigir a dashboard
```

### 4.3. Crear/Editar Testamento (Cifrado Híbrido)

```
1. Cliente:
   a. Usuario escribe contenido del testamento
   b. Usuario ingresa claves de cuentas bancarias
   c. Click en "Guardar Borrador"
   
   CIFRADO HÍBRIDO:
   d. Generar llave AES temporal (256 bits)
   e. Cifrar datos con AES-256-GCM
   f. Obtener llave pública RSA del servidor
   g. Cifrar llave AES con RSA pública
   h. Enviar "sobre digital": {
        datosCifrados,
        claveAESCifrada,
        iv,
        authTag
      }

2. Servidor:
   a. Descifrar llave AES con RSA privada del servidor
   b. Descifrar datos con AES-256-GCM
   c. Obtener: contenido, cuentas_bancarias
   
   CIFRADO PARA BD:
   d. Generar llave maestra AES (desde .env)
   e. Generar IV aleatorio para contenido
   f. Cifrar contenido con AES-256-CBC
   g. Generar IV aleatorio para cuentas
   h. Cifrar cuentas con AES-256-CBC
   i. Guardar en BD: {
        contenido_cifrado,
        iv_contenido,
        cuentas_cifradas,
        iv_cuentas,
        estado: 'draft'
      }
   j. Retornar: success + testamento_id
```

### 4.4. Firmar Testamento (Firma Digital)

```
1. Cliente:
   a. Usuario revisa testamento final
   b. Click en "Firmar Testamento"
   c. Solicitar llave privada del usuario (generada o importada)
   
   FIRMA DIGITAL:
   d. Obtener contenido del testamento
   e. Generar hash SHA-256 del contenido
   f. Firmar hash con llave privada RSA del usuario
   g. Preparar datos con cifrado híbrido:
      - testamento_id
      - firma_digital (base64)
      - hash_original
   h. Enviar con cifrado híbrido al servidor

2. Servidor:
   a. Descifrar datos (híbrido)
   b. Obtener llave pública del usuario desde BD
   
   VERIFICACIÓN DE FIRMA:
   c. Verificar firma con llave pública
   d. Comparar hash
   e. Si válido:
      - Actualizar BD: firma_digital, hash_original
      - Cambiar estado a 'firmado'
      - Timestamp firmado_en
   f. Retornar: success + verificación
```

### 4.5. Consultar Testamento

```
1. Cliente:
   a. Solicitar testamento (con token JWT)
   b. Enviar testamento_id con cifrado híbrido

2. Servidor:
   a. Verificar autenticación (JWT)
   b. Verificar permisos (usuario dueño o ejecutor)
   
   DESCIFRADO DE BD:
   c. Obtener de BD: contenido_cifrado, iv_contenido
   d. Descifrar con llave maestra AES + IV
   e. Obtener datos originales
   
   CIFRADO HÍBRIDO PARA RESPUESTA:
   f. Cifrar respuesta con híbrido
   g. Enviar al cliente

3. Cliente:
   a. Descifrar respuesta (híbrido)
   b. Mostrar contenido al usuario
```

---

## 5. Gestión de Llaves

### 5.1. Llave Maestra AES (Base de Datos)

**Ubicación:** Variable de entorno `.env`

```
# 32 bytes (256 bits) en hexadecimal
DB_ENCRYPTION_KEY=a1b2c3d4e5f6...
```

**Generación:**
```javascript
const key = crypto.randomBytes(32).toString('hex');
```

**Uso:**
- Cifrar/descifrar contenido de testamentos en BD
- Cifrar/descifrar claves de cuentas bancarias
- Cifrar/descifrar datos de beneficiarios

**Consideraciones:**
- NUNCA commitear al repositorio
- Backup seguro en ubicación separada
- Rotación periódica (con migración de datos)
- Acceso restringido solo al servidor

### 5.2. Vector de Inicialización (IV)

**Ubicación:** Columna en la base de datos (por registro)

**Generación:**
```javascript
const iv = crypto.randomBytes(16); // 16 bytes para AES
```

**Características:**
- Único para cada registro cifrado
- No necesita ser secreto
- Almacenado junto al dato cifrado
- 16 bytes (128 bits) para AES-256-CBC

### 5.3. Par de Llaves RSA (Usuario)

**Generación:** Al registrar usuario

```javascript
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});
```

**Almacenamiento:**
- **Llave Pública:** Base de datos (tabla usuarios)
- **Llave Privada:** 
  - Opción 1: Descarga para el usuario (recomendado)
  - Opción 2: Almacenar cifrada con contraseña del usuario
  - Opción 3: Generación en cliente (Web Crypto API)

**Uso:**
- **Privada:** Firmar testamentos
- **Pública:** Verificar firmas

### 5.4. Par de Llaves RSA (Servidor - Híbrido)

**Generación:** Al iniciar servidor (o una vez)

```javascript
// Generación única, guardar en archivos
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

fs.writeFileSync('keys/server_public.pem', publicKey);
fs.writeFileSync('keys/server_private.pem', privateKey);
```

**Almacenamiento:**
- Archivos PEM en servidor
- Permisos restrictivos (solo lectura servidor)
- NO commitear al repositorio

**Uso:**
- **Pública:** Compartir con clientes para cifrado híbrido
- **Privada:** Descifrar llaves AES recibidas

---

## 6. Endpoints del API

### Autenticación

```
POST /api/auth/register
  Body: { username, email, password }
  Response: { success, token, message }

POST /api/auth/login
  Body: { username, password }
  Response: { success, token, user: { id, username, email } }

POST /api/auth/logout
  Headers: { Authorization: Bearer <token> }
  Response: { success, message }

GET /api/auth/me
  Headers: { Authorization: Bearer <token> }
  Response: { success, user: { id, username, email, public_key } }
```

### Cifrado Híbrido

```
GET /api/crypto/server-public-key
  Response: { success, publicKey: <PEM> }
```

### Testamentos

```
POST /api/testamentos/crear
  Headers: { Authorization: Bearer <token> }
  Body (cifrado híbrido): {
    datosCifrados,
    claveAESCifrada,
    iv,
    authTag
  }
  Contenido descifrado: {
    contenido,
    cuentas_bancarias: [{ banco, cuenta, password }],
    beneficiarios: [{ nombre, relacion, porcentaje }]
  }
  Response (cifrado híbrido): { success, testamento_id }

PUT /api/testamentos/:id
  Headers: { Authorization: Bearer <token> }
  Body: Similar a crear
  Response: { success, message }

POST /api/testamentos/:id/firmar
  Headers: { Authorization: Bearer <token> }
  Body (cifrado híbrido): {
    firma_digital,
    hash_original
  }
  Response: { success, verificado: true/false }

GET /api/testamentos/:id
  Headers: { Authorization: Bearer <token> }
  Response (cifrado híbrido): {
    testamento: {
      contenido,
      cuentas_bancarias,
      beneficiarios,
      firmado,
      fecha_firma
    }
  }

GET /api/testamentos/mis-testamentos
  Headers: { Authorization: Bearer <token> }
  Response: { success, testamentos: [...] }
```

### Verificación

```
POST /api/verificar/firma
  Body: { testamento_id, firma, contenido }
  Response: { success, valido: true/false, firmante }
```

---

## 7. Verificaciones Requeridas

### 7.1. Verificar Hash bcrypt en BD

```sql
SELECT id, username, password_hash FROM usuarios;
```

Resultado esperado:
```
id | username | password_hash
1  | marco    | $2b$10$K8zP.../... (60 caracteres)
```

### 7.2. Verificar Campo Cifrado en BD

```sql
SELECT id, contenido_cifrado, iv_contenido FROM testamentos WHERE id = 1;
```

Resultado esperado:
```
id | contenido_cifrado | iv_contenido
1  | a7f3e9d2c4...    | 3f8b1e9a...
```

El contenido_cifrado debe ser ilegible (hex o base64).

### 7.3. Verificar Firma Digital

Endpoint: `POST /api/verificar/firma`

```javascript
// Proceso interno
const valid = crypto.verify(
  'sha256',
  Buffer.from(contenido_original),
  {
    key: public_key_pem,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING
  },
  Buffer.from(firma, 'base64')
);
```

### 7.4. Verificar Cifrado Híbrido

Logging en servidor:
```
[INFO] Datos recibidos cifrados con híbrido
[INFO] Llave AES descifrada exitosamente
[INFO] Datos descifrados correctamente
```

---

## 8. Diagrama de Flujo - Cifrado Híbrido

```
CLIENTE                                    SERVIDOR

1. Generar Llave AES temporal
   ↓
2. Cifrar datos con AES-GCM
   ↓
3. Obtener Public Key del servidor  ────→  4. Enviar Public Key RSA
   ↓
5. Cifrar Llave AES con RSA pública
   ↓
6. Preparar "Sobre Digital":
   - Datos Cifrados (AES)
   - Llave AES Cifrada (RSA)
   - IV
   - AuthTag
   ↓
7. Enviar "Sobre Digital" ──────────────→  8. Recibir "Sobre Digital"
                                           ↓
                                          9. Descifrar Llave AES con RSA privada
                                           ↓
                                          10. Descifrar Datos con AES-GCM
                                           ↓
                                          11. Procesar datos originales
                                           ↓
                                          12. Cifrar respuesta (híbrido)
                                           ↓
13. Recibir respuesta cifrada  ←───────── 14. Enviar respuesta
    ↓
15. Descifrar respuesta
    ↓
16. Mostrar al usuario
```

---

## 9. Seguridad Adicional

### Headers HTTP (Helmet)
- Content-Security-Policy
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Strict-Transport-Security

### Rate Limiting
- Login: 5 intentos / 15 minutos
- API: 100 requests / minuto

### Logging de Auditoría
- Todos los accesos a testamentos
- Intentos de login fallidos
- Modificaciones de testamentos
- Firmas digitales

### Validación de Datos
- express-validator en todos los endpoints
- Sanitización de inputs
- Validación de tipos de datos

---

## 10. Consideraciones de Producción

### Base de Datos
- Migrar de SQLite a PostgreSQL
- Backup automático diario
- Cifrado de backups

### Llaves
- Usar HSM (Hardware Security Module) para llaves del servidor
- Key rotation programada
- Backup cifrado de llaves en ubicación segura

### Monitoreo
- Alertas de accesos sospechosos
- Monitoreo de intentos de firma inválidos
- Logs centralizados

---

**Documento de Arquitectura v1.0**  
Marco Antonio Gómez Olvera - UTEQ
