@echo off
setlocal
cd /d "%~dp0"
echo ==============================
echo Terminal Chat (Rahasia) - Menu
echo ==============================
echo 1) Jalankan SERVER
echo 2) Jalankan CLIENT
echo.
set /p mode=Pilihan (1/2): 
echo.
if "%mode%"=="1" (
  py -3 chat.py --mode server
  goto :eof
)
if "%mode%"=="2" (
  py -3 chat.py --mode client
  goto :eof
)
echo Pilihan tidak valid.
pause
