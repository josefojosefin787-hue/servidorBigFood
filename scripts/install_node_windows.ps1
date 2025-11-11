<# install_node_windows.ps1
   Intenta instalar Node.js LTS con winget/choco y luego ejecuta npm install en el proyecto.
#>

function Write-Info($m){ Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Write-Warn($m){ Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Err($m){ Write-Host "[ERROR] $m" -ForegroundColor Red }

Write-Info "Comprobando si Node.js ya está instalado..."
try{ $node = & node -v 2>$null; $npm = & npm -v 2>$null } catch { $node = $null; $npm = $null }

if ($node -and $npm) {
  Write-Info "Node ya instalado: $node  (npm $npm)"
} else {
  Write-Info "Node no encontrado en PATH. Intentando instalar con winget/choco..."
  $hasWinget = (Get-Command winget -ErrorAction SilentlyContinue) -ne $null
  $hasChoco = (Get-Command choco -ErrorAction SilentlyContinue) -ne $null

  if ($hasWinget) {
    Write-Info "winget detectado. Instalando Node.js LTS..."
    winget install OpenJS.NodeJS.LTS -e
  } elseif ($hasChoco) {
    Write-Info "Chocolatey detectado. Instalando nodejs-lts..."
    choco install nodejs-lts -y
  } else {
    Write-Warn "Ni winget ni Chocolatey detectados."
    Write-Host "Descarga manual desde: https://nodejs.org/es/" -ForegroundColor Yellow
    exit 0
  }

  Start-Sleep -Seconds 3
  try{ $node = & node -v 2>$null; $npm = & npm -v 2>$null } catch { $node = $null; $npm = $null }
  if ($node -and $npm) { Write-Info "Instalación completada: $node (npm $npm)" } else { Write-Warn "No se detectó node tras la instalación. Reinicia PowerShell y vuelve a intentarlo."; exit 1 }
}

Write-Info "Instalando dependencias del proyecto (npm install)..."
try {
  npm install
  Write-Info "Instalación de dependencias completada."
} catch {
  Write-Err "npm install falló. Revisa la salida anterior para errores."; exit 2
}

Write-Info "Asegurando que 'pg' esté instalado (driver Postgres)..."
try { npm install pg --save; Write-Info "pg instalado (o ya estaba presente)." } catch { Write-Warn "No se pudo instalar 'pg' automáticamente." }

Write-Info "Hecho. Para probar: node server.js"
Write-Host "Ejemplo para definir DB temporalmente en PowerShell:" -ForegroundColor Gray
Write-Host "  $env:DATABASE_URL = 'postgres://usuario:pass@host:5432/nombredb'" -ForegroundColor Gray
Write-Host "  node server.js" -ForegroundColor Gray
