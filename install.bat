@echo off
setlocal enabledelayedexpansion

:: Configuration
set "XEON_DIR=%USERPROFILE%\.xeo"
set "XEON_BIN=%XEON_DIR%\bin"
set "BINARY_NAME=xeo.exe"
set "REPO=arozoid/xeo"
set "BASE_URL=https://github.com/%REPO%/releases/latest/download"

echo --- installing xeo ---

:: 1. Create directories
if not exist "%XEON_BIN%" mkdir "%XEON_BIN%"

:: 2. Architecture detection (Windows is usually x64)
:: Windows doesn't use 'uname', so we check the PROCESSOR_ARCHITECTURE
set "ARTIFACT=xeo-windows.exe"
if "%PROCESSOR_ARCHITECTURE%"=="ARM64" (
    set "ARTIFACT=xeo-windows-arm64.exe"
)

:: 3. Handle binary installation
if exist "target\release\%BINARY_NAME%" (
    echo found local build, installing...
    copy /Y "target\release\%BINARY_NAME%" "%XEON_BIN%\%BINARY_NAME%"
) else if exist "%BINARY_NAME%" (
    echo found binary in current folder, installing...
    copy /Y "%BINARY_NAME%" "%XEON_BIN%\%BINARY_NAME%"
) else (
    echo Downloading %ARTIFACT% from GitHub...
    set "DOWNLOAD_URL=%BASE_URL%/%ARTIFACT%"
    
    :: Use PowerShell for the download (built into Windows)
    powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '%DOWNLOAD_URL%' -OutFile '%XEON_BIN%\%BINARY_NAME%'"
    
    if %ERRORLEVEL% NEQ 0 (
        echo error: download failed.
        exit /b 1
    )
)

:: 4. Update PATH (Persistent Windows environment change)
:: This checks if the directory is already in the PATH
echo %PATH% | findstr /C:"%XEON_BIN%" >nul
if %ERRORLEVEL% NEQ 0 (
    echo Adding %XEON_BIN% to PATH...
    :: Use setx to make the change permanent for the user
    setx PATH "%PATH%;%XEON_BIN%"
    echo PATH updated. Please restart your terminal to use xeo.
)

echo --- success: xeo installed to %XEON_BIN% ---
pause