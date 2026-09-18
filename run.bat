@echo off
setlocal

title NEXO Privilege Gate v0.4

cd /d "%~dp0"

echo.
echo ==============================================
echo  NEXO Privilege Gate v0.4
echo ==============================================
echo.

where python >nul 2>nul

if errorlevel 1 (
    echo [ERROR] Python was not found.
    echo.
    echo Install Python 3.11 or newer and make sure
    echo "Add Python to PATH" is enabled.
    echo.
    pause
    exit /b 1
)

echo [1/3] Checking Python...
python --version

echo.
echo [2/3] Running security regression tests...
echo.

python -m unittest discover -s tests -p "test_*.py" -v

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

python server.py

echo.
echo NEXO stopped.
echo.

pause
