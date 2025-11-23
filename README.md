# Gestor de Testamentos Digitales - Sistema de Seguridad Criptográfica

**Alumno:** Marco Antonio Gómez Olvera  
**Materia:** Seguridad Informática  
**Profesor:** Brandon Efren Venegas Olvera  
**Institución:** Universidad Tecnológica de Querétaro (UTEQ)  
**Fecha:** Noviembre 2025

---

## Descripción

Sistema de gestión de testamentos digitales que implementa **4 capas de seguridad criptográfica** para garantizar la confidencialidad, integridad, autenticidad y no repudio de la información testamentaria.

---

## 4 Capas de Seguridad Implementadas

### 1. Login Seguro (Autenticación)
- **Tecnología:** bcrypt
- **Implementación:** Hash de contraseñas con bcrypt (10 rounds)
- **Verificación:** Las contraseñas NUNCA se almacenan en texto plano
- **Protección:** Identidad del usuario

### 2. Datos en Reposo (Cifrado Simétrico)
- **Tecnología:** AES-256-CBC
- **Implementación:** Cifrado de contenido de testamentos y claves bancarias
- **Gestión de Llaves:** Llave maestra en variable de entorno + IV único por registro
- **Protección:** Confidencialidad de información almacenada

### 3. Autenticidad y No Repudio (Firma Digital)
- **Tecnología:** RSA-2048 con SHA-256
- **Implementación:** Firma digital del contenido del testamento
- **Verificación:** Llave pública almacenada en BD
- **Protección:** Integridad y autoría de testamentos

### 4. Defensa en Profundidad (Cifrado Híbrido)
- **Tecnología:** RSA-2048 + AES-256-GCM
- **Implementación:** "Sobre Digital" para comunicación cliente-servidor
- **Proceso:** Cifrado híbrido end-to-end
- **Protección:** Confidencialidad en transmisión

---

## Stack Tecnológico

### Backend
- Node.js v16+
- Express.js
- SQLite3
- bcrypt (hash de contraseñas)
- crypto (nativo Node.js)
- jsonwebtoken (JWT)
- helmet (headers de seguridad)
- winston (logging)

### Frontend
- HTML5
- CSS3
- JavaScript (Vanilla)
- Web Crypto API

---

## Estructura del Proyecto

```
testamentos_digitales/
├── backend/
│   ├── src/
│   │   ├── database/
│   │   │   ├── schema.sql           # Esquema de BD
│   │   │   ├── init.js              # Inicializador
│   │   │   └── connection.js        # Conexión con promesas
│   │   ├── security/
│   │   │   ├── AuthService.js       # CAPA 1: bcrypt
│   │   │   ├── EncryptionService.js # CAPA 2: AES-256
│   │   │   ├── SignatureService.js  # CAPA 3: RSA Firma
│   │   │   └── HybridCryptoService.js # CAPA 4: Híbrido
│   │   ├── middleware/
│   │   │   ├── auth.js              # JWT verificación
│   │   │   ├── security.js          # Rate limiting, etc.
│   │   │   └── validation.js        # Validación de datos
│   │   ├── controllers/
│   │   │   ├── authController.js
│   │   │   ├── testamentoController.js
│   │   │   └── verificacionController.js
│   │   ├── routes/
│   │   │   ├── auth.js
│   │   │   ├── testamentos.js
│   │   │   └── verificacion.js
│   │   ├── models/
│   │   │   ├── Usuario.js
│   │   │   └── Testamento.js
│   │   ├── utils/
│   │   │   └── logger.js
│   │   └── server.js                # Servidor principal
│   ├── keys/                        # Llaves RSA del servidor
│   ├── database/                    # Archivo SQLite
│   ├── logs/                        # Logs de auditoría
│   ├── package.json
│   ├── .env                         # Variables de entorno
│   └── .gitignore
│
├── frontend/
│   ├── index.html                   # Página principal
│   ├── login.html
│   ├── dashboard.html
│   ├── crear-testamento.html
│   ├── firmar-testamento.html
│   ├── css/
│   │   └── styles.css
│   └── js/
│       ├── auth.js                  # Login/Registro
│       ├── crypto.js                # Web Crypto API
│       ├── hybrid.js                # CAPA 4: Híbrido
│       ├── signature.js             # CAPA 3: Firma
│       ├── testamento.js            # Lógica de testamentos
│       └── utils.js
│
├── ARQUITECTURA.md                  # Documentación de arquitectura
├── INSTRUCCIONES.md                 # Instrucciones de verificación
└── README.md                        # Este archivo
```

---

## Instalación

### Requisitos Previos
- Node.js v16 o superior
- npm

### Paso 1: Clonar Repositorio

```bash
git clone <url-repositorio>
cd testamentos_digitales
```

### Paso 2: Instalar Dependencias del Backend

```bash
cd backend
npm install
```

### Paso 3: Configurar Variables de Entorno

```bash
cp .env.example .env
```

Editar `.env` y generar las llaves:

```bash
# Generar JWT_SECRET
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# Generar DB_ENCRYPTION_KEY (32 bytes para AES-256)
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Copiar los valores generados en `.env`:

```env
JWT_SECRET=<valor_generado_1>
DB_ENCRYPTION_KEY=<valor_generado_2>
```

### Paso 4: Inicializar Base de Datos

```bash
npm run init-db
```

Debe mostrar:
```
Base de datos inicializada correctamente
Tablas creadas:
  - usuarios
  - testamentos
  - beneficiarios
  ...
```

### Paso 5: Generar Llaves RSA del Servidor

```bash
node src/security/generateServerKeys.js
```

Esto crea:
- `keys/server_public.pem`
- `keys/server_private.pem`

### Paso 6: Iniciar Servidor

```bash
npm start
```

O en modo desarrollo:
```bash
npm run dev
```

El servidor debe iniciar en `http://localhost:3000`

---

## Uso del Sistema

### 1. Registro de Usuario

```
Frontend: /login.html
POST /api/auth/register
Body: {
  username: "marco",
  email: "marco@example.com",
  password: "Password123!"
}
```

El sistema:
- Hashea la contraseña con bcrypt
- Genera par de llaves RSA para el usuario
- Almacena en BD: username, email, password_hash, public_key_pem
- Retorna JWT token

### 2. Login

```
POST /api/auth/login
Body: {
  username: "marco",
  password: "Password123!"
}
```

El sistema:
- Verifica password con bcrypt.compare()
- Genera JWT token
- Retorna token + datos de usuario

### 3. Crear Testamento

```
Frontend: /crear-testamento.html
POST /api/testamentos/crear

Proceso:
1. Usuario escribe contenido del testamento
2. Usuario ingresa claves de cuentas bancarias
3. Cliente cifra datos con cifrado híbrido (CAPA 4)
4. Servidor descifra datos (híbrido)
5. Servidor cifra datos con AES-256 para BD (CAPA 2)
6. Servidor guarda en BD
```

### 4. Firmar Testamento

```
Frontend: /firmar-testamento.html
POST /api/testamentos/:id/firmar

Proceso:
1. Cliente genera hash SHA-256 del contenido
2. Cliente firma hash con llave privada RSA del usuario (CAPA 3)
3. Cliente envía firma con cifrado híbrido
4. Servidor verifica firma con llave pública (CAPA 3)
5. Servidor actualiza testamento en BD
6. Testamento queda FIRMADO (no modificable)
```

### 5. Consultar Testamento

```
GET /api/testamentos/:id

Proceso:
1. Servidor verifica autenticación (JWT)
2. Servidor descifra datos de BD (AES-256)
3. Servidor cifra respuesta con híbrido
4. Cliente descifra y muestra
```

---

## Verificaciones Requeridas

### 1. Verificar Hash bcrypt en BD

Abrir base de datos:
```bash
sqlite3 database/testamentos.db
```

Ejecutar query:
```sql
SELECT id, username, password_hash FROM usuarios;
```

**Resultado esperado:**
```
id | username | password_hash
1  | marco    | $2b$10$K8zP...  (60 caracteres)
```

El hash debe empezar con `$2b$10$` (bcrypt con 10 rounds).

### 2. Verificar Campo Cifrado en BD

```sql
SELECT id, contenido_cifrado, iv_contenido FROM testamentos WHERE id = 1;
```

**Resultado esperado:**
```
id | contenido_cifrado           | iv_contenido
1  | a7f3e9d2c4b8f1a9...        | 3f8b1e9a2d4c...
```

El contenido_cifrado debe ser texto ilegible (hexadecimal).

### 3. Verificar Firma Digital

```sql
SELECT id, firma_digital, hash_original, estado FROM testamentos WHERE estado = 'firmado';
```

**Resultado esperado:**
```
id | firma_digital  | hash_original | estado
1  | a7b3f9d2...   | 8f3a1c2d...  | firmado
```

**Verificación programática:**

```
POST /api/verificar/firma
Body: { testamento_id: 1 }

Response: {
  success: true,
  valido: true,
  firmante: "marco",
  fecha_firma: "2025-11-23T..."
}
```

### 4. Verificar Cifrado Híbrido

**Logs del servidor al crear testamento:**

```
[INFO] Recibiendo datos con cifrado híbrido
[INFO] Descifrando llave AES con RSA privada del servidor
[INFO] Llave AES descifrada: 32 bytes
[INFO] Descifrando datos con AES-256-GCM
[INFO] Datos descifrados correctamente
[INFO] Contenido recibido: 245 caracteres
```

**Verificar en consola del navegador:**

```javascript
console.log('Generando llave AES temporal...');
console.log('Cifrando datos con AES-256-GCM...');
console.log('Cifrando llave AES con RSA pública del servidor...');
console.log('Enviando sobre digital al servidor...');
```

---

## Flujo de Cifrado Híbrido (Sobre Digital)

```
CLIENTE                                    SERVIDOR

1. Generar Llave AES-256 temporal
   ↓
2. Cifrar datos con AES-GCM
   ↓
3. Obtener RSA Public Key del servidor ─→  4. Enviar Public Key
   ↓
5. Cifrar Llave AES con RSA pública
   ↓
6. Preparar "Sobre Digital":
   {
     datosCifrados,      # AES-GCM
     claveAESCifrada,    # RSA-OAEP
     iv,                 # 12 bytes
     authTag             # 16 bytes
   }
   ↓
7. Enviar "Sobre Digital" ─────────────→  8. Recibir paquete
                                          ↓
                                         9. Descifrar Llave AES
                                            con RSA privada
                                          ↓
                                         10. Descifrar datos
                                             con AES-GCM
                                          ↓
                                         11. Procesar datos
                                          ↓
                                         12. Cifrar respuesta
                                             (híbrido)
                                          ↓
13. Recibir respuesta cifrada ←─────────14. Enviar respuesta
    ↓
15. Descifrar con llave privada RSA
    ↓
16. Mostrar al usuario
```

---

## Endpoints del API

### Autenticación

```
POST /api/auth/register          # Registrar usuario
POST /api/auth/login             # Login
POST /api/auth/logout            # Logout
GET  /api/auth/me                # Obtener usuario actual
```

### Cifrado Híbrido

```
GET /api/crypto/server-public-key  # Obtener llave pública del servidor
```

### Testamentos

```
POST   /api/testamentos/crear              # Crear testamento (híbrido)
GET    /api/testamentos/mis-testamentos    # Listar mis testamentos
GET    /api/testamentos/:id                # Obtener testamento (híbrido)
PUT    /api/testamentos/:id                # Actualizar testamento (híbrido)
POST   /api/testamentos/:id/firmar         # Firmar testamento (híbrido)
DELETE /api/testamentos/:id                # Eliminar testamento
```

### Verificación

```
POST /api/verificar/firma        # Verificar firma de testamento
```

---

## Seguridad Adicional

### Headers HTTP (Helmet)
- `Content-Security-Policy`
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Strict-Transport-Security`

### Rate Limiting
- Login: 5 intentos / 15 minutos
- API general: 100 requests / minuto
- Endpoints de firma: 10 / minuto

### Validación de Datos
- express-validator en todos los endpoints
- Sanitización de inputs
- Validación de tipos

### Logging de Auditoría
- Todas las operaciones se registran en `audit_log`
- Intentos de login fallidos
- Modificaciones de testamentos
- Firmas digitales
- Logs en `logs/combined.log` y `logs/security.log`

---

## Consideraciones de Producción

**NO USAR EN PRODUCCIÓN SIN:**

1. **Base de Datos**
   - Migrar de SQLite a PostgreSQL
   - Backup automático cifrado
   - Replicación

2. **Llaves**
   - Usar HSM (Hardware Security Module)
   - Key rotation programada
   - Backup en ubicación segura separada

3. **HTTPS**
   - Certificado SSL/TLS válido
   - Forzar HTTPS (no HTTP)

4. **Monitoreo**
   - Alertas de accesos sospechosos
   - Monitoreo de intentos de firma inválidos
   - Logs centralizados

5. **Autenticación**
   - 2FA (Two-Factor Authentication)
   - Recuperación segura de cuenta

---

## Entregables

1. **Repositorio Público:** GitHub/GitLab con todo el código
2. **Documentación:**
   - `README.md` (este archivo)
   - `ARQUITECTURA.md` (diseño completo)
   - `INSTRUCCIONES.md` (verificaciones)
3. **Código Fuente:**
   - Backend completo funcional
   - Frontend completo funcional
   - 4 capas de seguridad implementadas
4. **Demostración:**
   - Video o capturas de pantalla
   - Verificación de cada capa
   - Logs del sistema

---

## Autor

**Marco Antonio Gómez Olvera**  
Seguridad Informática - UTEQ  
Profesor: Brandon Efren Venegas Olvera

---

## Licencia

Este proyecto es con fines educativos para la materia de Seguridad Informática en la UTEQ.
