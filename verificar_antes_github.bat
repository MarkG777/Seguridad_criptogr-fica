@echo off
color 0B
echo.
echo ================================================================
echo   CHECKLIST ANTES DE SUBIR A GITHUB
echo ================================================================
echo.

echo [1/6] Verificando archivo .gitignore...
if exist "backend\.gitignore" (
    echo     [OK] .gitignore existe
) else (
    echo     [ERROR] Falta .gitignore
)
echo.

echo [2/6] Verificando documentacion...
if exist "README.md" (
    echo     [OK] README.md existe
) else (
    echo     [ERROR] Falta README.md
)
if exist "ARQUITECTURA.md" (
    echo     [OK] ARQUITECTURA.md existe
) else (
    echo     [ERROR] Falta ARQUITECTURA.md
)
if exist "EVIDENCIA_4_CAPAS.md" (
    echo     [OK] EVIDENCIA_4_CAPAS.md existe
) else (
    echo     [ERROR] Falta EVIDENCIA_4_CAPAS.md
)
echo.

echo [3/6] Verificando PDF...
if exist "proyecto.pdf" (
    echo     [OK] proyecto.pdf existe
) else (
    echo     [ERROR] Falta proyecto.pdf
)
echo.

echo [4/6] Verificando codigo backend...
if exist "backend\src\security\AuthService.js" (
    echo     [OK] AuthService.js (CAPA 1) existe
) else (
    echo     [ERROR] Falta AuthService.js
)
if exist "backend\src\security\EncryptionService.js" (
    echo     [OK] EncryptionService.js (CAPA 2) existe
) else (
    echo     [ERROR] Falta EncryptionService.js
)
if exist "backend\src\security\SignatureService.js" (
    echo     [OK] SignatureService.js (CAPA 3) existe
) else (
    echo     [ERROR] Falta SignatureService.js
)
if exist "backend\src\security\HybridCryptoService.js" (
    echo     [OK] HybridCryptoService.js (CAPA 4) existe
) else (
    echo     [ERROR] Falta HybridCryptoService.js
)
echo.

echo [5/6] Verificando test-client.js...
if exist "backend\test-client.js" (
    echo     [OK] test-client.js existe
) else (
    echo     [ERROR] Falta test-client.js
)
echo.

echo [6/6] Verificando que .env NO se suba...
if exist "backend\.env" (
    echo     [WARNING] .env existe - DEBE estar en .gitignore
    echo     [INFO] Verifica que .gitignore contenga: .env
) else (
    echo     [OK] .env no existe o esta ignorado
)
echo.

echo ================================================================
echo   ARCHIVOS LISTOS PARA GITHUB
echo ================================================================
echo.
echo   Si todo esta [OK], puedes ejecutar:
echo.
echo   git init
echo   git add .
echo   git commit -m "Proyecto completo con 4 capas de seguridad"
echo.
echo ================================================================
echo.
pause
