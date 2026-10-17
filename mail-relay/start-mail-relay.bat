@echo off
title EcoClaim mail relay
cd /d "%~dp0"
if not exist config.json (
  echo config.json not found.
  echo Copy config.example.json to config.json and fill in your SMTP details.
  pause
  exit /b 1
)
python mail_relay.py
pause
