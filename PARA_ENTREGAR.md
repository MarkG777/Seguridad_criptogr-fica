# PROYECTO: Gestor de Testamentos Digitales
## 4 Capas de Seguridad Criptográfica

**Alumno:** Marco Antonio Gómez Olvera  
**Materia:** Seguridad Informática  
**Profesor:** Brandon Efren Venegas Olvera  
**Institución:** UTEQ  
**Fecha:** 23 de Noviembre 2025

---

## 📁 ARCHIVOS PARA ENTREGAR

### 1. Documentación (4 archivos)

| Archivo | Contenido | Propósito |
|---------|-----------|-----------|
| **proyecto.pdf** ⭐ | **Documento LaTeX completo** | **Resumen ejecutivo con evidencias** |
| **ARQUITECTURA.md** | Diseño técnico completo | Stack, diagramas, flujos de las 4 capas |
| **README.md** | Documentación principal | Instalación, uso, tecnologías |
| **EVIDENCIA_4_CAPAS.md** | Pruebas y verificaciones | Evidencia de cumplimiento de requisitos |

### 2. Código Fuente

```
backend/
├── src/
│   ├── controllers/         # Controladores de la API
│   ├── security/            # ⭐ LAS 4 CAPAS AQUÍ ⭐
│   │   ├── AuthService.js          # CAPA 1: bcrypt
│   │   ├── EncryptionService.js    # CAPA 2: AES-256
│   │   ├── SignatureService.js     # CAPA 3: RSA Firma
│   │   └── HybridCryptoService.js  # CAPA 4: Híbrido
│   ├── models/              # Modelos de BD
│   ├── routes/              # Rutas de la API
│   ├── middleware/          # Seguridad, auth, validación
│   ├── database/            # Schema SQL y conexión
│   └── server.js            # Servidor principal
├── test-client.js           # Script de pruebas
├── package.json             # Dependencias
└── .env.example             # Ejemplo de configuración
```

### 3. Base de Datos

```
database/testamentos.db      # SQLite con datos de prueba
```

---

## ✅ CUMPLIMIENTO DE REQUISITOS

### Requisito 1: Login Seguro ✅

**Implementación:**
- bcrypt con 10 rounds
- Hash almacenado en BD
- Contraseñas NUNCA en texto plano

**Archivo:** `backend/src/security/AuthService.js`

**Verificación en BD:**
```sql
SELECT password_hash FROM usuarios WHERE id = 1;
-- Resultado: $2b$10$FiZMIjvruS8Dr9D5EvLJKeoecwFEzAvcaT9eT5bFAluqx6ktW1JPe
```

✅ **Hash bcrypt verificado** (ver EVIDENCIA_4_CAPAS.md)

---

### Requisito 2: Datos en Reposo (AES-256) ✅

**Implementación:**
- Algoritmo: AES-256-CBC
- Llave maestra: 32 bytes (256 bits) en .env
- IV único por registro (16 bytes)

**Archivo:** `backend/src/security/EncryptionService.js`

**Campos cifrados:**
- Contenido del testamento
- Contraseñas de cuentas bancarias

**Verificación en BD:**
```sql
SELECT contenido_cifrado, iv_contenido FROM testamentos WHERE id = 1;
-- Resultado: d82adc99ab314012e6c2ea892a1f082e... | 467af8ad23432716...
```

✅ **Contenido ilegible** - cifrado correctamente (ver EVIDENCIA_4_CAPAS.md)

---

### Requisito 3: Firma Digital (RSA) ✅

**Implementación:**
- Algoritmo: RSA-PSS-2048 con SHA-256
- Llave privada del usuario
- Verificación con llave pública

**Archivo:** `backend/src/security/SignatureService.js`

**Flujo:**
1. Usuario firma testamento con llave privada
2. Sistema verifica con llave pública
3. Estado cambia a "firmado"

**Verificación en BD:**
```sql
SELECT firma_digital, hash_original, estado FROM testamentos WHERE id = 1;
-- Resultado: R25VggCXf1NM20Xk... | 5a57dde2d3e7df12... | firmado
```

✅ **Firma verificada** - garantías de autenticidad, integridad y no repudio (ver EVIDENCIA_4_CAPAS.md)

---

### Requisito 4: Cifrado Híbrido (Sobre Digital) ✅

**Implementación:**
- RSA-OAEP-2048 para cifrar llave AES
- AES-256-GCM para cifrar datos
- Defense in Depth aplicado

**Archivo:** `backend/src/security/HybridCryptoService.js`

**Flujo:**
1. Cliente obtiene llave pública RSA del servidor
2. Cliente genera llave AES temporal
3. Cliente cifra datos con AES
4. Cliente cifra llave AES con RSA pública
5. Servidor descifra llave AES con RSA privada
6. Servidor descifra datos con AES

**Verificación:**
- Logs del servidor muestran el proceso completo
- Datos viajan cifrados extremo a extremo

✅ **Sobre digital funcionando** (ver EVIDENCIA_4_CAPAS.md)

---

## 🚀 INSTRUCCIONES DE EJECUCIÓN

### Paso 1: Instalar Dependencias
```bash
cd backend
npm install
```

### Paso 2: Generar Llaves
```bash
node src/utils/generateKeys.js
```
Copiar las llaves generadas a un archivo `.env`

### Paso 3: Inicializar Base de Datos
```bash
npm run init-db
```

### Paso 4: Iniciar Servidor
```bash
npm start
```

Debe mostrar:
```
✓ Servidor corriendo en http://localhost:3000

4 Capas de Seguridad Activas:
  [1] Login Seguro - bcrypt para contraseñas
  [2] Cifrado Simétrico - AES-256-CBC para BD
  [3] Firma Digital - RSA-2048 para testamentos
  [4] Cifrado Híbrido - RSA + AES-GCM para comunicación
```

### Paso 5: Ejecutar Pruebas Automatizadas
```bash
# En otra terminal
node test-client.js
```

**Resultado esperado:**
```
╔════════════════════════════════════════╗
║  RESULTADO: 5/5 PRUEBAS EXITOSAS       ║
╚════════════════════════════════════════╝
🎉 TODAS LAS CAPAS FUNCIONANDO 🎉
```

### Paso 6: Verificar en Base de Datos
```bash
sqlite3 database/testamentos.db

# Ver hash bcrypt
SELECT id, username, password_hash FROM usuarios;

# Ver contenido cifrado
SELECT id, contenido_cifrado, iv_contenido FROM testamentos;

# Ver firma digital
SELECT id, firma_digital, hash_original, estado FROM testamentos WHERE estado = 'firmado';
```

---

## 📊 RESULTADOS DE PRUEBAS

| Test | Descripción | Resultado |
|------|-------------|-----------|
| 1 | Obtener llave pública servidor (CAPA 4) | ✅ OK |
| 2 | Registrar usuario (CAPA 1 - bcrypt) | ✅ OK |
| 3 | Crear testamento (CAPA 2 + CAPA 4) | ✅ OK |
| 4 | Firmar testamento (CAPA 3 + CAPA 4) | ✅ OK |
| 5 | Verificar en base de datos | ✅ OK |

**Total: 5/5 pruebas exitosas** ✅

**Evidencias fotográficas:** 6 capturas incluidas en `proyecto.pdf`:
- Captura 6: Verificación de hash bcrypt en base de datos ⭐ **NUEVA**
- Capturas 1-5: Pruebas automatizadas y verificaciones

Ver detalles en `EVIDENCIA_4_CAPAS.md` y `proyecto.pdf`

---

## 🛡️ TECNOLOGÍAS UTILIZADAS

### Backend
- Node.js v18+
- Express.js 4.18
- SQLite3 5.1

### Seguridad
- **bcrypt 5.1** - Hash de contraseñas (CAPA 1)
- **crypto (nativo)** - AES-256, RSA, SHA-256 (CAPAS 2, 3, 4)
- **jsonwebtoken 9.0** - Tokens JWT
- **express-validator 7.0** - Validación
- **helmet 7.1** - Headers de seguridad
- **winston 3.11** - Logging

### Algoritmos Implementados
- **bcrypt** - 10 rounds de salt
- **AES-256-CBC** - Cifrado simétrico
- **RSA-PSS-2048** - Firma digital
- **RSA-OAEP-2048** - Cifrado asimétrico (híbrido)
- **AES-256-GCM** - Cifrado autenticado (híbrido)
- **SHA-256** - Hash de contenido

---

## 📖 DOCUMENTOS PARA REVISAR

### 1. ARQUITECTURA.md
Contiene:
- Diseño completo del sistema
- Diagramas de las 4 capas
- Flujo de cada operación
- Gestión de llaves
- Endpoints de la API

### 2. README.md
Contiene:
- Descripción del proyecto
- Instalación paso a paso
- Uso de la aplicación
- Tecnologías utilizadas
- Consideraciones de seguridad

### 3. EVIDENCIA_4_CAPAS.md ⭐ **MÁS IMPORTANTE**
Contiene:
- Pruebas de cada capa
- Capturas de pantalla
- Verificaciones en BD
- Logs del sistema
- Resultados completos

---

## ✅ CHECKLIST DE ENTREGA

- ✅ Repositorio con código fuente completo
- ✅ ARQUITECTURA.md con diseño técnico
- ✅ README.md con documentación de uso
- ✅ EVIDENCIA_4_CAPAS.md con pruebas
- ✅ Script de pruebas automatizadas (test-client.js)
- ✅ Base de datos con datos de prueba
- ✅ Las 4 capas implementadas y verificadas
- ✅ Hash bcrypt verificado en BD
- ✅ Contenido cifrado verificado en BD
- ✅ Firma digital verificada en BD
- ✅ Cifrado híbrido verificado en logs

---

## 🎯 RESUMEN EJECUTIVO

**Proyecto:** Sistema de gestión de testamentos digitales con 4 capas de seguridad criptográfica

**Caso de uso específico:**
- Asignación de bienes digitales
- Mensajes póstumos
- Firma digital del testamento
- Cifrado de contenido y contraseñas bancarias

**Resultado:**
- ✅ 100% de requisitos cumplidos
- ✅ 5/5 pruebas automatizadas exitosas
- ✅ Todas las capas verificadas en BD
- ✅ Código documentado y funcional
- ✅ Evidencias completas incluidas

**Estado:** COMPLETO Y LISTO PARA ENTREGAR

---

**Marco Antonio Gómez Olvera y su equipo**  
**Seguridad Informática - UTEQ**  
**Noviembre 2025**
