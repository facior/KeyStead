@echo off
title KeyStead Manager
cd /d "%~dp0"
python main.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Wystapil blad podczas uruchamiania. Upewnij sie, ze zaleznosci sa zainstalowane:
    echo pip install -r requirements.txt
    pause
)
