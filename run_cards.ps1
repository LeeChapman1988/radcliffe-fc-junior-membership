# run_cards.ps1
# Set SMTP environment variables for this session
$env:SMTP_HOST = "smtp.office365.com"
$env:SMTP_PORT = "587"
$env:SMTP_USER = "lee.chapman@radcliffejuniors.com"
$env:SMTP_PASSWORD = "Halo345_"
$env:FROM_EMAIL = "lee.chapman@radcliffejuniors.com"

# Optionally echo them to check
Write-Host "SMTP_HOST =" $env:SMTP_HOST
Write-Host "SMTP_USER =" $env:SMTP_USER

# Run the app using the venv's Python (no need to 'activate' in the script)
.\venv\Scripts\python.exe app.py
