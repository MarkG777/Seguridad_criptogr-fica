@echo off
color 0A
echo.
echo ========================================================================
echo   VERIFICACION DE HASH BCRYPT EN BASE DE DATOS - CAPA 1
echo ========================================================================
echo.
echo   Mostrando usuarios con sus hashes bcrypt...
echo.
echo ========================================================================
echo.

sqlite3 database\testamentos.db ".mode column" ".headers on" "SELECT id, username, email, password_hash FROM usuarios;"

echo.
echo ========================================================================
echo.
echo   VERIFICACION:
echo   - El hash debe comenzar con $2b$10$ (bcrypt con 10 rounds)
echo   - El hash es completamente ilegible (NO texto plano)
echo   - Cada usuario tiene un salt unico
echo.
echo ========================================================================
echo.
echo   CAPTURA DE PANTALLA: Presiona PrintScreen ahora para capturar
echo.
pause
