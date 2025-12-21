@echo off
setlocal

:: Configuration
set "XEON_DIR=%USERPROFILE%\.xeo"

echo --- uninstalling xeo ---

:: 1. Remove the directory and all contents
:: /S removes all directories and files in the specified directory
:: /Q runs in quiet mode (no confirmation prompt)
if exist "%XEON_DIR%" (
    rmdir /S /Q "%XEON_DIR%"
    if %ERRORLEVEL% EQU 0 (
        echo removed: %XEON_DIR%
    ) else (
        echo error: could not fully remove %XEON_DIR%. Is a xeo process still running?
    )
) else (
    echo info: %XEON_DIR% directory not found.
)

echo.
echo --- success: xeo files have been removed ---
echo Note: The .xeo\bin folder may still be in your PATH environment variable.
echo You can manually remove it from "Edit the system environment variables" if desired.
echo.

pause