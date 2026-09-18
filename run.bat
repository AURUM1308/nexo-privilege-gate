@echo off
setlocal

title NEXO Privilege Gate v0.4

cd /d "%~dp0"

echo.
echo ==============================================
echo  NEXO Privilege Gate v0.4
echo ==============================================
echo.

REM ------------------------------------------------
REM Find a real Python interpreter
REM ------------------------------------------------

set "PYTHON_CMD="

py --version >nul 2>&1
if not errorlevel 1 (
    set "PYTHON_CMD=py"
    goto :python_found
)

python --version >nul 2>&1
if not errorlevel 1 (
    set "PYTHON_CMD=python"
    goto :python_found
)

echo [ERROR] A working Python installation was not found.
echo.
echo Install Python 3.11 or newer.
echo.
pause
exit /b 1


:python_found

echo [1/3] Checking Python...
%PYTHON_CMD% --version

echo.
echo [2/3] Running security regression tests...
echo.

%PYTHON_CMD% -m unittest discover -s tests -p "test_*.py" -v

if errorlevel 1 (
    echo.
    echo ==============================================
    echo  TESTS FAILED
    echo ==============================================
    echo.
    echo NEXO will NOT start because one or more
    echo security regression tests failed.
    echo.
    pause
    exit /b 1
)

echo.
echo ==============================================
echo  ALL TESTS PASSED
echo ==============================================
echo.

echo [3/3] Starting local enforcement server...
echo.
echo A private Human Control URL will appear below.
echo Open that URL in your browser.
echo.
echo Press Ctrl+C to stop NEXO.
echo.

%PYTHON_CMD% server.py

echo.
echo NEXO stopped.
echo.

pause
