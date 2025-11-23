# EVIDENCIA DE LAS 4 CAPAS DE SEGURIDAD

**Alumno:** Marco Antonio Gómez Olvera  
**Materia:** Seguridad Informática  
**Profesor:** Brandon Efren Venegas Olvera  
**Fecha:** 23 de Noviembre 2025

---

## ✅ CUMPLIMIENTO TOTAL DE REQUISITOS

| Requisito | Implementado | Probado | Verificado BD | Evidencia |
|-----------|--------------|---------|---------------|-----------|
| **1. Login Seguro (bcrypt)** | ✅ | ✅ | ✅ | Hash verificado |
| **2. Datos en Reposo (AES-256)** | ✅ | ✅ | ✅ | Cifrado verificado |
| **3. Firma Digital (RSA)** | ✅ | ✅ | ✅ | Firma verificada |
| **4. Cifrado Híbrido** | ✅ | ✅ | ✅ | Logs verificados |

---

# CAPA 1: Login Seguro (bcrypt)

## Implementación
- **Archivo:** `AuthService.js`
- **Tecnología:** bcrypt con 10 rounds
- **Función:** Hash de contraseñas

## Prueba Realizada
```bash
POST /api/auth/register
{
  "username": "marco",
  "password": "Password123!"
}
```

**Resultado:** ✅ Usuario registrado, token JWT generado

## Verificación en BD
```sql
SELECT password_hash FROM usuarios WHERE id = 1;
```

**Resultado:**
```
$2b$10$FiZMIjvruS8Dr9D5EvLJKeoecwFEzAvcaT9eT5bFAluqx6ktW1JPe
```

✅ **VERIFICADO:** Hash bcrypt correcto (comienza con $2b$10$)

**Evidencia:** Ver capturas de pantalla 3 y 5

---

# CAPA 2: Datos en Reposo (AES-256)

## Implementación
- **Archivo:** `EncryptionService.js`
- **Algoritmo:** AES-256-CBC
- **Llave Maestra:** 32 bytes (256 bits) en .env
- **IV:** Único por registro (16 bytes)

## Gestión de Llaves
```
DB_ENCRYPTION_KEY=9a59a4246d0f98ca59833884d2f5add26356317bebdfcb9e9530f50b9ab03860
```

## Campos Cifrados
- `contenido_cifrado` - Testamento completo
- `cuentas_bancarias_cifradas` - Passwords de bancos

## Prueba Realizada
```bash
POST /api/testamentos/crear
```

**Datos sensibles enviados:**
- Contenido del testamento
- Contraseñas de cuentas bancarias

## Verificación en BD
```sql
SELECT contenido_cifrado, iv_contenido FROM testamentos WHERE id = 1;
```

**Resultado:**
```
d82adc99ab314012e6c2ea892a1f082e... | 467af8ad23432716f6235892579ff209
```

✅ **VERIFICADO:** Contenido completamente ilegible (cifrado con AES-256)

**Evidencia:** Ver captura de pantalla 5

---

# CAPA 3: Firma Digital (RSA)

## Implementación
- **Archivo:** `SignatureService.js`
- **Algoritmo:** RSA-PSS-2048 con SHA-256
- **Par de llaves:** Generado al registrar usuario

## Flujo de Firma
1. Usuario genera hash SHA-256 del testamento
2. Usuario firma con su llave privada RSA
3. Servidor verifica con llave pública
4. Si válida, marca testamento como "firmado"

## Prueba Realizada
```bash
POST /api/testamentos/1/firmar
```

**Proceso:**
```
[FIRMA] Hash SHA-256: 5a57dde2d3e7df12c8a4c96712e534ca...
[FIRMA] Firma generada con RSA-PSS
[SERVIDOR] Firma verificada: ✅ true
```

## Verificación en BD
```sql
SELECT firma_digital, hash_original, estado FROM testamentos WHERE id = 1;
```

**Resultado:**
```
R25VggCXf1NM20Xk0RFPBdSScm... | 5a57dde2d3e7df12c8a4c96712e534ca... | firmado
```

✅ **VERIFICADO:** Firma digital RSA almacenada y verificada

**Garantías:**
- Autenticidad (solo el usuario pudo firmar)
- Integridad (hash garantiza no modificación)
- No repudio (no puede negar que firmó)

**Evidencia:** Ver captura de pantalla 5

---

# CAPA 4: Cifrado Híbrido (Sobre Digital)

## Implementación
- **Archivo:** `HybridCryptoService.js`
- **Algoritmo:** RSA-OAEP-2048 + AES-256-GCM
- **Llaves servidor:** Generadas automáticamente

## Flujo del Sobre Digital

### Cliente (Cifrar)
1. Genera llave AES temporal (32 bytes)
2. Cifra datos con AES-256-GCM
3. Cifra llave AES con RSA pública del servidor
4. Envía paquete completo

### Servidor (Descifrar)
1. Descifra llave AES con RSA privada
2. Descifra datos con AES-256-GCM
3. Procesa datos originales

## Prueba Realizada
```bash
GET /api/crypto/server-public-key
POST /api/testamentos/crear (con sobre digital)
```

**Logs del proceso:**
```
[HIBRIDO] Cifrando datos...
  1. Llave AES-256 generada: 32 bytes
  2. IV generado: 12 bytes
  3. Datos cifrados con AES-256-GCM
  4. Llave AES cifrada con RSA del servidor
[HIBRIDO] Sobre digital creado ✅

[SERVIDOR] Descifrando sobre digital...
  1. Llave AES descifrada: 32 bytes
  2. Datos descifrados correctamente
[SERVIDOR] Sobre digital procesado ✅
```

✅ **VERIFICADO:** Cifrado híbrido funcionando

**Defense in Depth:**
- Capa aplicación (cifrado híbrido)
- Independiente de HTTPS
- Seguridad extremo a extremo

**Evidencia:** Ver capturas de pantalla 2, 4 y 5

---

# RESULTADO DE PRUEBAS AUTOMATIZADAS

```
╔════════════════════════════════════════╗
║  PRUEBAS COMPLETAS                     ║
║  4 Capas de Seguridad Criptográfica    ║
╚════════════════════════════════════════╝

TEST 1: Llave Pública Servidor (CAPA 4) ... ✅ OK
TEST 2: Registrar Usuario (CAPA 1) ........ ✅ OK
TEST 3: Crear Testamento (CAPA 2+4) ....... ✅ OK
TEST 4: Firmar Testamento (CAPA 3+4) ...... ✅ OK
TEST 5: Verificar en BD ................... ✅ OK

╔════════════════════════════════════════╗
║  RESULTADO: 5/5 PRUEBAS EXITOSAS       ║
╚════════════════════════════════════════╝

🎉 TODAS LAS CAPAS FUNCIONANDO 🎉
```

**Evidencia:** Ver capturas de pantalla 4 y 5

---

# VERIFICACIONES EN BASE DE DATOS

## Hash bcrypt
```
$2b$10$FiZMIjvruS8Dr9D5EvLJKe...
✅ Comienza con $2b$10$ (bcrypt 10 rounds)
```

## Contenido cifrado AES-256
```
d82adc99ab314012e6c2ea892a1f082e... (384 chars)
IV: 467af8ad23432716f6235892579ff209
✅ Completamente ilegible
```

## Firma digital RSA
```
R25VggCXf1NM20Xk0RFPBdSScm+yzYmO... (344 chars)
Hash: 5a57dde2d3e7df12c8a4c96712e534ca...
Estado: firmado
✅ Firma verificada
```

---

# INSTRUCCIONES DE VERIFICACIÓN

## Iniciar Servidor
```bash
cd backend
npm install
node src/utils/generateKeys.js  # Copiar llaves a .env
npm run init-db
npm start
```

## Ejecutar Pruebas
```bash
node test-client.js
```

## Verificar en BD
```bash
sqlite3 database/testamentos.db

SELECT password_hash FROM usuarios;
SELECT contenido_cifrado FROM testamentos;
SELECT firma_digital, estado FROM testamentos;
```

---

# CONCLUSIÓN

✅ **Las 4 Capas de Seguridad están:**
- Implementadas correctamente
- Probadas exitosamente
- Verificadas en base de datos
- Documentadas con evidencias

**Caso de uso:** Gestor de Testamentos Digitales  
**Estado:** COMPLETO Y FUNCIONAL

---

**Marco Antonio Gómez Olvera**  
Seguridad Informática - UTEQ  
Noviembre 2025
