-- Base de Datos para Sistema de Testamentos Digitales
-- 4 Capas de Seguridad Criptográfica

-- Tabla de Usuarios
-- CAPA 1: Login Seguro (password_hash con bcrypt)
-- CAPA 3: Firma Digital (public_key_pem para verificar firmas)
CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,  -- bcrypt hash
    public_key_pem TEXT NOT NULL, -- Llave pública RSA para firmas
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    activo BOOLEAN DEFAULT 1
);

-- Tabla de Testamentos
-- CAPA 2: Datos en Reposo (contenido_cifrado con AES-256)
-- CAPA 3: Firma Digital (firma_digital con RSA)
CREATE TABLE IF NOT EXISTS testamentos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER NOT NULL,
    
    -- Contenido cifrado con AES-256-CBC
    contenido_cifrado TEXT NOT NULL,
    iv_contenido TEXT NOT NULL, -- Vector de inicialización (16 bytes hex)
    
    -- Claves de cuentas bancarias cifradas
    cuentas_bancarias_cifradas TEXT,
    iv_cuentas TEXT, -- Vector de inicialización separado
    
    -- Firma digital (CAPA 3)
    firma_digital TEXT, -- Firma RSA en base64
    hash_original TEXT, -- SHA-256 del contenido original
    firmado_en DATETIME,
    
    -- Metadata
    estado TEXT DEFAULT 'borrador' CHECK(estado IN ('borrador', 'firmado', 'ejecutado')),
    titulo TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

-- Tabla de Beneficiarios
-- CAPA 2: Datos sensibles cifrados
CREATE TABLE IF NOT EXISTS beneficiarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    testamento_id INTEGER NOT NULL,
    
    -- Datos cifrados con AES-256
    nombre_cifrado TEXT NOT NULL,
    relacion_cifrada TEXT,
    porcentaje_cifrado TEXT,
    iv TEXT NOT NULL, -- Vector de inicialización
    
    orden INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (testamento_id) REFERENCES testamentos(id) ON DELETE CASCADE
);

-- Tabla de Mensajes Póstumos
-- CAPA 2: Mensajes cifrados
CREATE TABLE IF NOT EXISTS mensajes_postumos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    testamento_id INTEGER NOT NULL,
    beneficiario_id INTEGER,
    
    -- Mensaje cifrado
    mensaje_cifrado TEXT NOT NULL,
    iv TEXT NOT NULL,
    
    tipo TEXT DEFAULT 'general' CHECK(tipo IN ('general', 'individual')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (testamento_id) REFERENCES testamentos(id) ON DELETE CASCADE,
    FOREIGN KEY (beneficiario_id) REFERENCES beneficiarios(id) ON DELETE SET NULL
);

-- Tabla de Auditoría
-- Registro de todas las operaciones importantes
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER,
    accion TEXT NOT NULL,
    entidad TEXT, -- testamento, usuario, etc.
    entidad_id INTEGER,
    ip_address TEXT,
    user_agent TEXT,
    detalles TEXT,
    exitoso BOOLEAN DEFAULT 1,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE SET NULL
);

-- Tabla de Sesiones (para invalidar tokens JWT si es necesario)
CREATE TABLE IF NOT EXISTS sesiones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER NOT NULL,
    token_id TEXT NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    revocado BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

-- Índices para mejorar rendimiento
CREATE INDEX IF NOT EXISTS idx_usuarios_username ON usuarios(username);
CREATE INDEX IF NOT EXISTS idx_usuarios_email ON usuarios(email);
CREATE INDEX IF NOT EXISTS idx_testamentos_usuario ON testamentos(usuario_id);
CREATE INDEX IF NOT EXISTS idx_testamentos_estado ON testamentos(estado);
CREATE INDEX IF NOT EXISTS idx_beneficiarios_testamento ON beneficiarios(testamento_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_usuario ON audit_log(usuario_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_sesiones_token ON sesiones(token_id);
CREATE INDEX IF NOT EXISTS idx_sesiones_usuario ON sesiones(usuario_id);

-- Triggers para actualizar updated_at
CREATE TRIGGER IF NOT EXISTS update_testamentos_timestamp 
AFTER UPDATE ON testamentos
BEGIN
    UPDATE testamentos SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- Vistas útiles
CREATE VIEW IF NOT EXISTS v_testamentos_resumen AS
SELECT 
    t.id,
    t.usuario_id,
    u.username,
    t.titulo,
    t.estado,
    CASE WHEN t.firma_digital IS NOT NULL THEN 1 ELSE 0 END as firmado,
    t.firmado_en,
    t.created_at,
    t.updated_at,
    COUNT(b.id) as num_beneficiarios
FROM testamentos t
JOIN usuarios u ON t.usuario_id = u.id
LEFT JOIN beneficiarios b ON t.id = b.testamento_id
GROUP BY t.id;

-- Vista de auditoría de testamentos
CREATE VIEW IF NOT EXISTS v_audit_testamentos AS
SELECT 
    a.id,
    a.usuario_id,
    u.username,
    a.accion,
    a.entidad_id as testamento_id,
    a.timestamp,
    a.ip_address
FROM audit_log a
LEFT JOIN usuarios u ON a.usuario_id = u.id
WHERE a.entidad = 'testamento'
ORDER BY a.timestamp DESC;
