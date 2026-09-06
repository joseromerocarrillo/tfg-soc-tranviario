# ============================================================
# Filtrar trafico por subred desde capturas PCAPNG.GZ
# Windows + tshark - sin VM
# Temporales en SSD local, output final en USB
# ============================================================

# -- CONFIGURACION --------------------------------------------
$TShark     = "C:\Program Files\Wireshark\tshark.exe"
$MergeCap   = "C:\Program Files\Wireshark\mergecap.exe"
$InputDir   = "E:\capturas"          # USB - solo lectura
$OutputBase = "E:\analysis"          # USB - output final
$TmpBase    = "C:\tfg\tmp"           # SSD local - temporales

$LimiteGB = 5

$Subredes = @(
    @{
        Nombre = "ofimatica"
        Filtro = "ip.addr == 192.168.21.0/24"
        Output = "$OutputBase\ofimatica\ofimatica_192.168.21.0-24.pcapng"
    },
    @{
        Nombre = "scada"
        Filtro = "ip.addr == 192.168.2.0/24 or ip.addr == 192.168.5.0/24 or ip.addr == 192.168.12.0/24"
        Output = "$OutputBase\scada\scada_plcs.pcapng"
    }
)
# -------------------------------------------------------------

# ============================================================
# Comprobaciones
# ============================================================

if (-not (Test-Path $TShark)) {
    Write-Host "ERROR: tshark no encontrado en $TShark" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $MergeCap)) {
    Write-Host "ERROR: mergecap no encontrado en $MergeCap" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $InputDir)) {
    Write-Host "ERROR: no existe la carpeta de capturas: $InputDir" -ForegroundColor Red
    exit 1
}

New-Item -ItemType Directory -Force -Path $TmpBase | Out-Null

# ============================================================
# Funcion auxiliar: ejecuta tshark via BAT temporal
# Evita todos los problemas de escaping de PowerShell
# ============================================================

function Ejecutar-TShark {
    param(
        [string]$TShark,
        [string]$InputFile,
        [string]$Filtro,
        [string]$OutputFile,
        [string]$ErrLog
    )

    # Crear bat temporal con el comando exacto
    $BatFile = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.bat'
    $Contenido = "@echo off`r`n"
    $Contenido += "`"$TShark`" -n -q -r `"$InputFile`" -Y `"$Filtro`" -w `"$OutputFile`" 2>`"$ErrLog`"`r`n"
    [System.IO.File]::WriteAllText($BatFile, $Contenido, [System.Text.Encoding]::ASCII)

    $Proc = Start-Process -FilePath "cmd.exe" `
                          -ArgumentList "/c", "`"$BatFile`"" `
                          -NoNewWindow -Wait -PassThru

    Remove-Item $BatFile -ErrorAction SilentlyContinue
    return $Proc.ExitCode
}

# ============================================================
# Buscar capturas
# ============================================================

$Capturas = Get-ChildItem -Path $InputDir -Recurse -File |
    Where-Object { $_.Name -match "\.(pcap|pcapng)(\.gz)?$" } |
    Sort-Object Name

$Total = $Capturas.Count
Write-Host ""
Write-Host "Capturas detectadas: $Total" -ForegroundColor Cyan

if ($Total -eq 0) {
    Write-Host "ERROR: sin capturas en $InputDir" -ForegroundColor Red
    exit 1
}

# ============================================================
# Funcion de filtrado
# ============================================================

function Filtrar-Subred {
    param(
        [string]$Nombre,
        [string]$Filtro,
        [string]$OutputFile,
        [string]$TmpBase,
        [string]$TShark,
        [object[]]$Capturas,
        [int]$Total,
        [double]$LimiteGB
    )

    $OutputDir = Split-Path $OutputFile -Parent
    $TmpDir    = "$TmpBase\$Nombre\filtrados"
    $LogDir    = "$TmpBase\$Nombre\logs"
    $ResumeLog = "$OutputDir\procesados.txt"

    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    New-Item -ItemType Directory -Force -Path $TmpDir    | Out-Null
    New-Item -ItemType Directory -Force -Path $LogDir    | Out-Null

    # Resume
    $YaProcesados = @{}
    if (Test-Path $ResumeLog) {
        Get-Content $ResumeLog | ForEach-Object { $YaProcesados[$_] = $true }
        Write-Host "Resume activo: $($YaProcesados.Count) archivos ya procesados." -ForegroundColor DarkCyan
    }

    # Recalcular acumulado desde temporales existentes
    $AcumuladoBytes = 0
    Get-ChildItem "$TmpDir\filtrado_*.pcapng" -ErrorAction SilentlyContinue |
        ForEach-Object { $AcumuladoBytes += $_.Length }

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor White
    Write-Host " $Nombre -- Filtro: $Filtro" -ForegroundColor White
    Write-Host " Limite: $LimiteGB GB | Output: $OutputFile" -ForegroundColor White
    Write-Host " Temporales en: $TmpDir" -ForegroundColor White
    Write-Host "============================================================" -ForegroundColor White
    Write-Host ""

    $CountTotal      = 0
    $CountConTrafico = 0
    $CountSinTrafico = 0
    $CountError      = 0
    $CountSkip       = 0
    $LimiteBytes     = $LimiteGB * 1GB
    $TiempoInicio    = Get-Date

    foreach ($Pcap in $Capturas) {

        $CountTotal++

        if ($AcumuladoBytes -ge $LimiteBytes) {
            Write-Host "  Limite de $LimiteGB GB alcanzado. Parando $Nombre." -ForegroundColor Green
            break
        }

        $BaseName = $Pcap.Name
        $SafeName = $BaseName -replace '[^a-zA-Z0-9._-]', '_'
        $OutTmp   = "$TmpDir\filtrado_$SafeName.pcapng"
        $ErrLog   = "$LogDir\error_$SafeName.log"

        # Resume
        if ($YaProcesados.ContainsKey($BaseName)) {
            $CountSkip++
            Write-Host "[$CountTotal/$Total] SKIP -- $BaseName" -ForegroundColor DarkGray
            continue
        }

        $SizeMB = [math]::Round($Pcap.Length / 1MB, 1)

        # ETA
        $ProcesadosReales = $CountTotal - $CountSkip - 1
        $Elapsed = (Get-Date) - $TiempoInicio
        if ($ProcesadosReales -gt 0) {
            $ETASecs = [int]($Elapsed.TotalSeconds * ($Total - $CountTotal) / $ProcesadosReales)
            $ETAStr  = "{0}m {1}s" -f [math]::Floor($ETASecs / 60), ($ETASecs % 60)
        } else {
            $ETAStr = "calculando..."
        }

        $AcumuladoMB = [math]::Round($AcumuladoBytes / 1MB, 1)
        $LimiteMB    = $LimiteGB * 1024

        Write-Host "------------------------------------------------------------"
        Write-Host "[$CountTotal/$Total] $BaseName" -ForegroundColor Cyan
        Write-Host "  Entrada: $SizeMB MB | Acumulado: $AcumuladoMB MB / $LimiteMB MB | ETA: $ETAStr"
        Write-Host "  Inicio: $(Get-Date -Format 'HH:mm:ss')"

        # Monitor de progreso en job paralelo
        $MonitorJob = Start-Job -ScriptBlock {
            param($OutTmp, $BaseName)
            while ($true) {
                Start-Sleep -Seconds 10
                if (Test-Path $OutTmp) {
                    $sz = [math]::Round((Get-Item $OutTmp).Length / 1MB, 1)
                    Write-Output "  >> $(Get-Date -Format 'HH:mm:ss') | $BaseName | Salida parcial: $sz MB"
                } else {
                    Write-Output "  >> $(Get-Date -Format 'HH:mm:ss') | $BaseName | procesando..."
                }
            }
        } -ArgumentList $OutTmp, $BaseName

        # Ejecutar tshark via BAT temporal (evita problemas de escaping)
        $ExitCode = Ejecutar-TShark -TShark $TShark `
                                    -InputFile $Pcap.FullName `
                                    -Filtro $Filtro `
                                    -OutputFile $OutTmp `
                                    -ErrLog $ErrLog

        # Parar monitor y mostrar output
        Stop-Job $MonitorJob
        Receive-Job $MonitorJob | ForEach-Object { Write-Host $_ -ForegroundColor DarkYellow }
        Remove-Job $MonitorJob

        if ($ExitCode -ne 0) {
            Write-Host "  [ERROR] codigo $ExitCode -- ver $ErrLog" -ForegroundColor Red
            Remove-Item $OutTmp -ErrorAction SilentlyContinue
            $CountError++
        } elseif ((Test-Path $OutTmp) -and (Get-Item $OutTmp).Length -gt 0) {
            $SzOut = [math]::Round((Get-Item $OutTmp).Length / 1MB, 1)
            Write-Host "  [OK] trafico encontrado -- $SzOut MB" -ForegroundColor Green
            $AcumuladoBytes += (Get-Item $OutTmp).Length
            $CountConTrafico++
            Remove-Item $ErrLog -ErrorAction SilentlyContinue
        } else {
            Write-Host "  [VACIO] sin trafico de esta subred" -ForegroundColor DarkGray
            Remove-Item $OutTmp -ErrorAction SilentlyContinue
            Remove-Item $ErrLog -ErrorAction SilentlyContinue
            $CountSinTrafico++
        }

        Add-Content -Path $ResumeLog -Value $BaseName
        Write-Host "  Fin: $(Get-Date -Format 'HH:mm:ss')"
        Write-Host ""
    }

    # Resumen
    $TiempoTotal = (Get-Date) - $TiempoInicio
    Write-Host "============================================================" -ForegroundColor White
    Write-Host " Resumen $Nombre" -ForegroundColor White
    Write-Host "============================================================" -ForegroundColor White
    Write-Host " Procesados:   $($CountTotal - $CountSkip) / $Total"
    Write-Host " Con trafico:  $CountConTrafico"
    Write-Host " Sin trafico:  $CountSinTrafico"
    Write-Host " Errores:      $CountError"
    Write-Host " Saltados:     $CountSkip"
    Write-Host " Tiempo total: $([math]::Floor($TiempoTotal.TotalMinutes))m $($TiempoTotal.Seconds)s"
    Write-Host ""

    if ($CountConTrafico -eq 0) {
        Write-Host "Sin trafico encontrado para $Nombre." -ForegroundColor Yellow
        return
    }

    # Merge final
    $Temporales = Get-ChildItem "$TmpDir\filtrado_*.pcapng" -ErrorAction SilentlyContinue
    if ($Temporales.Count -eq 0) {
        Write-Host "Sin temporales para mergear." -ForegroundColor Yellow
        return
    }

    Write-Host "Combinando $($Temporales.Count) capturas..." -ForegroundColor Cyan
    Write-Host "Leyendo desde: $TmpDir (SSD local)"
    Write-Host "Escribiendo a: $OutputFile (USB)"

    $MergeArgs = @("-w", $OutputFile) + ($Temporales.FullName)
    & $MergeCap @MergeArgs

    if ((Test-Path $OutputFile) -and (Get-Item $OutputFile).Length -gt 0) {
        $SzFinal = [math]::Round((Get-Item $OutputFile).Length / 1MB, 1)
        Write-Host "[OK] Output final: $SzFinal MB" -ForegroundColor Green
        Write-Host "     $OutputFile"
    } else {
        Write-Host "ERROR: archivo final no generado." -ForegroundColor Red
    }

    Write-Host ""
    $Resp = Read-Host "Eliminar temporales de $TmpDir? [s/N]"
    if ($Resp -match "^[sS]$") {
        Remove-Item "$TmpDir\filtrado_*.pcapng" -Force
        Write-Host "Temporales eliminados."
    }
    Write-Host ""
}

# ============================================================
# Ejecucion
# ============================================================

foreach ($Sub in $Subredes) {
    Filtrar-Subred `
        -Nombre     $Sub.Nombre `
        -Filtro     $Sub.Filtro `
        -OutputFile $Sub.Output `
        -TmpBase    $TmpBase `
        -TShark     $TShark `
        -Capturas   $Capturas `
        -Total      $Total `
        -LimiteGB   $LimiteGB
}

Write-Host "============================================================" -ForegroundColor Green
Write-Host " TODO FINALIZADO" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
