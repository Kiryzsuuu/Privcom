@echo off
setlocal
cd /d "%~dp0"

REM ---- Find a Python command (py -3 preferred) ----
set "PYCMD="
where py >nul 2>nul
if %errorlevel%==0 (
  set "PYCMD=py -3"
) else (
  where python >nul 2>nul
  if %errorlevel%==0 (
    set "PYCMD=python"
  ) else (
    where python3 >nul 2>nul
    if %errorlevel%==0 (
      set "PYCMD=python3"
    )
  )
)

if "%PYCMD%"=="" (
  echo [!] Python was not found in PATH.
  echo     Install Python 3 and check "Add python.exe to PATH".
  echo     Then open a new CMD window and try again.
  pause
  exit /b 1
)

echo ==============================
echo Terminal Chat - Menu
echo ==============================
echo 1) Start SERVER
echo 2) Start CLIENT
echo.
set /p mode=Choice (1/2): 
echo.
if "%mode%"=="1" (
  %PYCMD% chat.py --mode server
  goto :eof
)
if "%mode%"=="2" (
  %PYCMD% chat.py --mode client
  goto :eof
)
echo Invalid choice.
pause
