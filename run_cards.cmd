@echo off
REM Set SMTP environment variables for this CMD session
set "SMTP_HOST=smtp.office365.com"
set "SMTP_PORT=587"
set "SMTP_USER=lee.chapman@radcliffejuniors.com"
set "SMTP_PASSWORD=Halo345_"
set "FROM_EMAIL=lee.chapman@radcliffejuniors.com"

echo SMTP_HOST = %SMTP_HOST%
echo SMTP_USER = %SMTP_USER%

REM Run the app using the venv's Python
venv\Scripts\python.exe app.py
