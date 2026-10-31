@echo off
rem Build SerialPill (env:pill) and flash The Pill on COM8. Log: flash-com8.log
cd /d "%~dp0"
set "PY=%USERPROFILE%\.serialpill-venv\Scripts\python.exe"
set "CA=%USERPROFILE%\.serialpill-venv\ca-bundle.pem"
set "PLATFORMIO_CORE_DIR=%USERPROFILE%\.serialpill-pio"
if exist "%CA%" (set "SSL_CERT_FILE=%CA%" & set "REQUESTS_CA_BUNDLE=%CA%" & set "PIP_CERT=%CA%" & set UV_NATIVE_TLS=1)
echo ===== build %DATE% %TIME% ===== > flash-com8.log
"%PY%" -m platformio run -e pill >> flash-com8.log 2>&1
if errorlevel 1 (echo BUILD FAILED >> flash-com8.log & goto end)
echo ===== upload COM8 ===== >> flash-com8.log
"%PY%" -m platformio run -e pill -t upload --upload-port COM8 >> flash-com8.log 2>&1
if errorlevel 1 (echo UPLOAD FAILED >> flash-com8.log & goto end)
echo DONE OK >> flash-com8.log
:end
echo Zakonczono - wynik w flash-com8.log
timeout /t 5
