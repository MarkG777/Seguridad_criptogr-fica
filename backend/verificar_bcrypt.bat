@echo off
echo ========================================
echo VERIFICACION DE HASH BCRYPT EN BD
echo ========================================
echo.
echo Abriendo base de datos SQLite...
echo.
sqlite3 database\testamentos.db "SELECT id, username, email, password_hash FROM usuarios;"
echo.
echo ========================================
echo.
pause
