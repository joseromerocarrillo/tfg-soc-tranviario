<#
.SYNOPSIS
    Orquestador de ataques de los casos practicos del TFG (SOC tranviario con Wazuh).

.DESCRIPTION
    Lanza el trafico/interaccion de ataque de cada caso practico contra el laboratorio
    real (contenedores Docker suricata-live / tcpreplay-sender / conpot-scada en el host
    Windows, y VM2 Ubuntu en 192.168.56.20). NO verifica las alertas en Wazuh (eso ocurre
    de forma asincrona en el Manager); su trabajo es DISPARAR el ataque de forma fiable y
    repetible, verificar los logs locales de los sensores e indicar que SID / regla revisar.

    Planos de deteccion:
      - HOST  (1,4,5): interaccion real (cliente Modbus, PUT FTP, login SSH).
      - RED   (2,3,5b,6,7): reinyeccion de PCAP con tcpreplay contra el sensor pasivo.

.PARAMETER Casos
    Lista de casos a ejecutar: 1 2 3 4 5 5b 6 7  o  all  (por defecto: all).
    Ej: -Casos 6,7    |    -Casos 5b    |    -Casos all

.PARAMETER Listar
    Muestra el catalogo de casos y sale.

.PARAMETER Pps
    Paquetes por segundo para los casos Suricata (defecto 200).

.PARAMETER ZeekPps
    Paquetes por segundo para el Caso 2 con Zeek (defecto 50, valor validado).

.PARAMETER NoVerificar
    No revisar eve.json tras los casos de red.

.PARAMETER NoMenu
    No abrir el menu interactivo de repeticion al terminar (modo desatendido).

.PARAMETER NoAutoStart
    No intentar arrancar/recrear los contenedores del lab en el preflight (solo reporta su estado).
    Por defecto el preflight SI intenta levantarlos: 'docker start' si existen parados, y
    'docker compose up -d' si no existen y hay un docker-compose.yml localizable.

.EXAMPLE
    .\Invoke-CasosPracticos.ps1
    .\Invoke-CasosPracticos.ps1 -Casos 6,7
    .\Invoke-CasosPracticos.ps1 -Casos 5b -Pps 50
    .\Invoke-CasosPracticos.ps1 -Casos 2 -ZeekPps 50
    .\Invoke-CasosPracticos.ps1 -Listar
#>

[CmdletBinding()]
param(
    [string[]]$Casos = @("all"),
    [switch]$Listar,
    [int]$Pps = 200,
    [int]$ZeekPps = 50,
    [switch]$NoVerificar,
    [switch]$NoMenu,
    [switch]$NoAutoStart
)

# =====================================================================================
# CONFIGURACION  (ajusta aqui si cambian nombres de contenedor, PCAPs o IPs)
# =====================================================================================
$CFG = @{
    # Contenedores Docker (host Windows)
    SuricataCtr   = "suricata-live"
    SenderCtr     = "tcpreplay-sender"
    ZeekCtr       = "zeek-live"          # Caso 2 (solo si esta levantado)
    ConpotCtr     = "conpot-scada"

    # Red Docker e interfaz interna de los sensores
    Iface         = "eth0"

    # Auto-arranque del lab (preflight). Fuente de verdad preferida: docker-compose.yml.
    # Si ComposeFile queda vacio se autodetecta en ComposeSearchDirs.
    ComposeFile       = ""
    ComposeSearchDirs = @($PSScriptRoot, "C:\tfg", "C:\tfg\docker", "C:\tfg\lab")

    # eve.json en el host (para verificacion local de casos de red)
    EvePath       = "C:\tfg\suricata\logs\eve.json"

    # PCAPs (rutas DENTRO de tcpreplay-sender: /pcaps). Si un PCAP no esta en /pcaps,
    # se busca en PcapSearchDirs (host) y se copia al sender con docker cp.
    PcapHostDir   = "C:\tfg\pcaps"        # (informativo) ya NO se usa: la conversion se hace dentro del sender
    PcapSearchDirs = @("C:\tfg\zeek\pcaps", "C:\tfg\pcaps", "C:\tfg\suricata\pcaps")
    Pcap = @{
        Caso2  = "ataque_modbus.pcap"
        Caso3  = "movimiento_lateral.pcap"
        Caso5b = @("http_en_502.pcap","ssh_en_8080.pcap","binario_aleatorio_3389.pcap")
        Caso6  = "escaneo_activos_servicios.pcap"
        Caso7  = "ssh_bruteforce_billetaje.pcap"
    }

    # Caso 2 - receta Zeek validada en el laboratorio
    ZeekImage      = "zeek/zeek:8.2.1"
    ZeekBin        = "/usr/local/zeek/bin/zeek"
    ZeekNet        = "suricata-lab"
    ZeekScriptDir  = "C:\tfg\zeek\scripts"   # contiene modbus_whitelist.zeek / modbus_acl.zeek
    ZeekLogDir     = "C:\tfg\zeek\logs"
    ZeekNoticePath = "C:\tfg\zeek\logs\notice.log"
    ZeekScript     = "modbus_whitelist.zeek"    # script principal

    # Caso 1 - Honeypot Conpot (puerto Modbus publicado en el host)
    ConpotHost    = "host.docker.internal"
    ConpotPort    = 502

    # Caso 4 / 5 - VM2 (servidores simulados)
    VM2           = "192.168.56.20"
    FtpDir        = "contenidos"
    SshUser       = "jose"
    SshPassword   = ""                   # opcional: si se rellena y hay plink.exe, login no interactivo
}

# SID Suricata / regla Wazuh esperados, por caso (solo informativo para la verificacion)
$ESPERADO = @{
    "1"  = @{ Plano="HOST"; Sid=@();                         Wazuh="100010/100011/100012" }
    "2"  = @{ Plano="RED";  Sid=@();                         Wazuh="100020/100021 (Zeek)" }
    "3"  = @{ Plano="RED";  Sid=@(9000002,9000003,9000004);  Wazuh="familia Caso 3" }
    "5b" = @{ Plano="RED";  Sid=@(5500001,5500007,5500008);  Wazuh="100050" }
    "6"  = @{ Plano="RED";  Sid=@(5500010,5500011);          Wazuh="100060" }
    "7"  = @{ Plano="RED";  Sid=@(5500020,5500021);          Wazuh="100070 (+100071 noche)" }
    "4"  = @{ Plano="HOST"; Sid=@();                         Wazuh="554/550 (FIM)" }
    "5"  = @{ Plano="HOST"; Sid=@();                         Wazuh="100030 (fuera de horario)" }
}

$ORDEN_ALL = @("1","2","3","5b","6","7","4","5")

# =====================================================================================
# UTILIDADES DE SALIDA
# =====================================================================================
function Write-Section($t){ Write-Host "`n=== $t ===" -ForegroundColor Cyan }
function Write-Ok($t){      Write-Host "  [OK]   $t" -ForegroundColor Green }
function Write-Warn($t){    Write-Host "  [!]    $t" -ForegroundColor Yellow }
function Write-Err($t){     Write-Host "  [ERR]  $t" -ForegroundColor Red }
function Write-Step($t){    Write-Host "  ->     $t" -ForegroundColor Gray }

# =====================================================================================
# PREFLIGHT
# =====================================================================================
$script:SURIMAC   = $null
$script:ZEEKMAC   = $null
$script:SENDERMAC = $null
$script:SenderToolsOk = $false
$script:SenderPyOk = $false

function Test-Ctr($name){
    if (-not $name) { return $false }
    $running = docker ps --filter "name=^/$name$" --filter "status=running" --format "{{.Names}}" 2>$null
    return ($running -eq $name)
}

function Get-Mac($ctr){
    try { return (docker exec $ctr sh -lc "cat /sys/class/net/$($CFG.Iface)/address" 2>$null).Trim() }
    catch { return $null }
}

function Test-CtrExists($name){
    # True si el contenedor existe (corriendo O parado).
    if (-not $name) { return $false }
    $found = docker ps -a --filter "name=^/$name$" --format "{{.Names}}" 2>$null
    return ($found -eq $name)
}

function Wait-CtrRunning{
    param([string]$name, [int]$TimeoutSec = 15)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
        if (Test-Ctr $name) { return $true }
        Start-Sleep -Milliseconds 700
    }
    return (Test-Ctr $name)
}

function Resolve-ComposeFile{
    # Devuelve la ruta del compose (config o autodetectada), o $null.
    if ($CFG.ComposeFile) {
        if (Test-Path $CFG.ComposeFile) { return $CFG.ComposeFile }
        Write-Warn "ComposeFile configurado no existe: $($CFG.ComposeFile)."
        return $null
    }
    foreach ($d in $CFG.ComposeSearchDirs) {
        if (-not $d) { continue }
        foreach ($n in @("docker-compose.yml","docker-compose.yaml","compose.yml","compose.yaml")) {
            $p = Join-Path $d $n
            if (Test-Path $p) { return $p }
        }
    }
    return $null
}

function Ensure-LabContainers{
    # Levanta los contenedores indicados. Estrategia en capas:
    #   1) parado pero existe  -> docker start (preserva config, barato)
    #   2) no existe + compose -> docker compose up -d (reconcilia todo el lab)
    #   3) no existe sin compose-> aviso (no se puede recrear sin receta)
    param([string[]]$Names)

    $pending = @()
    foreach ($n in $Names) {
        if (Test-Ctr $n) { Write-Ok "Contenedor '$n' Up."; continue }
        if (Test-CtrExists $n) {
            Write-Step "Contenedor '$n' parado: docker start..."
            docker start $n 2>&1 | Out-Null
            if (Wait-CtrRunning $n) {
                Write-Ok "Contenedor '$n' arrancado (docker start)."
            } else {
                Write-Err "'$n' no llego a 'running' tras docker start. Ultimas lineas del log:"
                docker logs $n 2>&1 | Select-Object -Last 12 | ForEach-Object { Write-Host "       $_" }
                $pending += $n
            }
        } else {
            Write-Warn "Contenedor '$n' NO existe (nunca creado)."
            $pending += $n
        }
    }

    if ($pending.Count -gt 0) {
        $compose = Resolve-ComposeFile
        if ($compose) {
            Write-Step "Recreando lo que falta con: docker compose -f `"$compose`" up -d"
            docker compose -f $compose up -d 2>&1 | ForEach-Object { Write-Host "       $_" }
            $stillDown = @()
            foreach ($n in $pending) {
                if (Wait-CtrRunning $n) { Write-Ok "Contenedor '$n' Up (compose)." } else { $stillDown += $n }
            }
            $pending = $stillDown
            if ($pending.Count -gt 0) {
                Write-Err "El compose no dejo 'running': $($pending -join ', '). Revisa nombres de servicio / errores arriba."
            }
        } else {
            Write-Warn "No se encontro docker-compose.yml (busque en: $($CFG.ComposeSearchDirs -join ', '))."
            Write-Warn "Sin receta no puedo recrear: $($pending -join ', '). Define `$CFG.ComposeFile o crea el compose."
        }
    }

    return ($pending.Count -eq 0)
}

function Ensure-SenderTools{
    if ($script:SenderToolsOk) { return $true }
    Write-Step "Asegurando tcpreplay/tcpdump en $($CFG.SenderCtr)..."
    docker exec $CFG.SenderCtr sh -lc "(command -v tcpreplay >/dev/null 2>&1 && command -v tcpdump >/dev/null 2>&1) || apk add --no-cache tcpreplay tcpdump >/dev/null 2>&1" 2>$null | Out-Null
    $script:SenderToolsOk = $true
    return $true
}

function Get-SenderPcapPath{
    # Devuelve la ruta DENTRO del sender donde esta (o queda copiado) el PCAP, o $null.
    # Orden: 1. /pcaps/<pcap>  2. /tmp/<pcap> ya copiado  3. buscar en host (PcapSearchDirs) y docker cp.
    param([string]$Pcap)
    if ((docker exec $CFG.SenderCtr sh -c "test -f /pcaps/$Pcap && echo SI || echo NO") -eq "SI") { return "/pcaps/$Pcap" }
    if ((docker exec $CFG.SenderCtr sh -c "test -f /tmp/$Pcap && echo SI || echo NO") -eq "SI")   { return "/tmp/$Pcap" }
    foreach ($d in $CFG.PcapSearchDirs) {
        $hp = Join-Path $d $Pcap
        if (Test-Path $hp) {
            Write-Step "PCAP '$Pcap' fuera de /pcaps; copiando desde $hp al sender..."
            docker cp $hp "$($CFG.SenderCtr):/tmp/$Pcap" | Out-Null
            if ((docker exec $CFG.SenderCtr sh -c "test -f /tmp/$Pcap && echo SI || echo NO") -eq "SI") { return "/tmp/$Pcap" }
        }
    }
    return $null
}

function Invoke-Preflight{
    Write-Section "Preflight"
    try { docker version --format "{{.Server.Version}}" *> $null } catch {}
    if ($LASTEXITCODE -ne 0) { Write-Err "Docker no responde. Arranca Docker Desktop."; return $false }
    Write-Ok "Docker operativo."

    # Contenedores de gestion generica (Zeek se trata aparte: tiene receta propia en el Caso 2).
    $manage = @($CFG.SuricataCtr, $CFG.SenderCtr, $CFG.ConpotCtr)

    if ($NoAutoStart) {
        foreach($c in @($manage + $CFG.ZeekCtr)){
            if (Test-Ctr $c) { Write-Ok "Contenedor '$c' Up." }
            else { Write-Warn "Contenedor '$c' NO esta corriendo (auto-arranque desactivado)." }
        }
    } else {
        Ensure-LabContainers -Names $manage | Out-Null

        # Zeek se recrea siempre al ejecutar el Caso 2 con la receta validada.
        if (Test-Ctr $CFG.ZeekCtr) {
            Write-Ok "Zeek '$($CFG.ZeekCtr)' esta Up; el Caso 2 lo recreara para limpiar estado y supresion."
        } elseif (Test-CtrExists $CFG.ZeekCtr) {
            Write-Warn "Zeek '$($CFG.ZeekCtr)' existe parado; el Caso 2 lo recreara."
        } else {
            Write-Warn "Zeek '$($CFG.ZeekCtr)' no existe; se creara al ejecutar el Caso 2."
        }
    }

    if (Test-Ctr $CFG.SenderCtr) { Ensure-SenderTools | Out-Null }

    if (Test-Ctr $CFG.SuricataCtr) { $script:SURIMAC   = Get-Mac $CFG.SuricataCtr; Write-Step "SURIMAC   = $script:SURIMAC" }
    if (Test-Ctr $CFG.ZeekCtr)     { $script:ZEEKMAC   = Get-Mac $CFG.ZeekCtr;     Write-Step "ZEEKMAC   = $script:ZEEKMAC" }
    if (Test-Ctr $CFG.SenderCtr)   { $script:SENDERMAC = Get-Mac $CFG.SenderCtr;   Write-Step "SENDERMAC = $script:SENDERMAC" }

    return $true
}

# =====================================================================================
# MOTOR DE REINYECCION (casos de red)
# =====================================================================================
function Get-LinkType{
    param([string]$Path)
    # Devuelve la primera linea de cabecera de tcpdump (incluye 'link-type EN10MB' etc.)
    return (docker exec $CFG.SenderCtr sh -c "tcpdump -nr $Path -c 1 2>&1 | head -1")
}

function Ensure-SenderPython{
    if ($script:SenderPyOk) { return $true }
    Write-Step "Asegurando python3+scapy en $($CFG.SenderCtr) (solo la 1a vez)..."
    docker exec $CFG.SenderCtr sh -c "command -v python3 >/dev/null 2>&1 || apk add --no-cache python3 py3-pip >/dev/null 2>&1; python3 -c 'import scapy' 2>/dev/null || pip install --break-system-packages -q scapy >/dev/null 2>&1" 2>$null | Out-Null
    $ok = (docker exec $CFG.SenderCtr sh -c "python3 -c 'import scapy' 2>/dev/null && echo SI || echo NO").Trim()
    $script:SenderPyOk = ($ok -eq "SI")
    if (-not $script:SenderPyOk) { Write-Err "No se pudo instalar scapy en $($CFG.SenderCtr)." }
    return $script:SenderPyOk
}

function Convert-PcapToEthernet{
    # Convierte $SrcPath (IP en crudo, DLT_RAW/DLT_IPV4) a Ethernet DENTRO del sender,
    # escribiendo /tmp/replay.pcap. Devuelve $true/$false.
    param([string]$SrcPath, [string]$SensorMac)
    if (-not (Ensure-SenderPython)) { return $false }
    $tmpPy = Join-Path $env:TEMP "_conv_eth.py"
@'
import os
from scapy.all import rdpcap, wrpcap, Ether, IP, IPv6
src = os.environ["SMAC"]; dst = os.environ["DMAC"]
pk = rdpcap(os.environ["INF"]); out = []
for p in pk:
    b = bytes(p)
    if IP in p:                    L = p[IP]
    elif IPv6 in p:                L = p[IPv6]
    elif b and (b[0] >> 4) == 6:   L = IPv6(b)
    else:                          L = IP(b)
    out.append(Ether(src=src, dst=dst) / L)
wrpcap(os.environ["OUTF"], out); print("WRAPPED", len(out))
'@ | Set-Content -Encoding ASCII $tmpPy
    docker cp $tmpPy "$($CFG.SenderCtr):/tmp/_conv_eth.py" | Out-Null
    Write-Step "PCAP sin Ethernet: envolviendo dentro de $($CFG.SenderCtr)"
    $o = docker exec -e "SMAC=$($script:SENDERMAC)" -e "DMAC=$SensorMac" -e "INF=$SrcPath" -e "OUTF=/tmp/replay.pcap" `
           $CFG.SenderCtr sh -c "python3 /tmp/_conv_eth.py" 2>&1
    if ($o -match "WRAPPED") { Write-Ok "Envuelto a /tmp/replay.pcap"; return $true }
    Write-Err "No se pudo envolver el PCAP:"; Write-Host ("       " + ($o -join "`n       ")); return $false
}

function Invoke-Replay{
    param([string]$Pcap, [string]$SensorMac, [int]$Pps)
    if (-not (Test-Ctr $CFG.SenderCtr)) { Write-Err "No existe '$($CFG.SenderCtr)'."; return $false }
    if (-not $SensorMac) { Write-Err "MAC del sensor no disponible (contenedor del sensor caido)."; return $false }
    Ensure-SenderTools | Out-Null

    $src = Get-SenderPcapPath $Pcap
    if (-not $src) {
        Write-Err "PCAP '$Pcap' no esta en /pcaps ni en las carpetas de busqueda: $($CFG.PcapSearchDirs -join ', ')."
        Write-Warn "Anade su carpeta del host a `$CFG.PcapSearchDirs o copialo a la carpeta montada como /pcaps."
        return $false
    }

    $lt = Get-LinkType $src
    if ($lt -match "EN10MB") {
        # PCAP con Ethernet: reescritura normal de MACs + replay
        $inner = "tcprewrite --enet-dmac=$SensorMac --enet-smac=$($script:SENDERMAC) --fixcsum " +
                 "--infile=$src --outfile=/tmp/replay.pcap && " +
                 "tcpreplay --intf1=$($CFG.Iface) --pps=$Pps /tmp/replay.pcap"
    } else {
        # PCAP de IP en crudo (p. ej. generado con Scapy): envolver con Ethernet y enviar directo
        Write-Warn "Link-type no Ethernet ($lt)."
        if (-not (Convert-PcapToEthernet -SrcPath $src -SensorMac $SensorMac)) { return $false }
        $inner = "tcpreplay --intf1=$($CFG.Iface) --pps=$Pps /tmp/replay.pcap"
    }

    Write-Step "Reinyectando $Pcap (--pps=$Pps) -> MAC $SensorMac"
    $out = docker exec $CFG.SenderCtr sh -lc $inner 2>&1
    $out | Where-Object { $_ -notmatch 'Unable to checksum ICMP' } | Out-Host
    if ($LASTEXITCODE -eq 0) { Write-Ok "Replay de $Pcap completado."; return $true }
    Write-Err "tcpreplay devolvio codigo $LASTEXITCODE para $Pcap."; return $false
}

# =====================================================================================
# CASOS
# =====================================================================================
function Invoke-Caso1{
    Write-Section "Caso 1 - Honeypot Conpot (cliente Modbus real)"
    if (-not (Test-Ctr $CFG.ConpotCtr)) { Write-Err "Conpot ('$($CFG.ConpotCtr)') no esta corriendo."; return $false }

    $tmpPy = Join-Path $env:TEMP "conpot_attack.py"
@'
import sys, os, inspect
try:
    from pymodbus.client import ModbusTcpClient
except Exception:
    from pymodbus.client.sync import ModbusTcpClient  # pymodbus 2.x
host = os.environ.get("CONPOT_HOST", "host.docker.internal")
port = int(os.environ.get("CONPOT_PORT", "502"))
c = ModbusTcpClient(host, port=port, timeout=5)
if not c.connect():
    print("NO_CONNECT"); sys.exit(2)

def devkw(fn):
    # El nombre del parametro de unidad cambia entre versiones: slave / unit / device_id
    params = inspect.signature(fn).parameters
    for n in ("slave", "unit", "device_id"):
        if n in params:
            return {n: 1}
    return {}

try:
    c.read_coils(0, count=8, **devkw(c.read_coils))                # FC1 reconocimiento
    c.read_holding_registers(0, count=8, **devkw(c.read_holding_registers))  # FC3 reconocimiento
    c.write_register(1, 0x1337, **devkw(c.write_register))         # FC6 escritura no autorizada
    print("OK")
except Exception as e:
    print("ERR", type(e).__name__, e)
finally:
    c.close()
'@ | Set-Content -Encoding ASCII $tmpPy
    $mount = ($tmpPy -replace '\\','/')
    Write-Step "Lanzando interaccion Modbus contra $($CFG.ConpotHost):$($CFG.ConpotPort)"
    $out = docker run --rm -e "CONPOT_HOST=$($CFG.ConpotHost)" -e "CONPOT_PORT=$($CFG.ConpotPort)" `
             -v "${mount}:/attack.py" python:3.12-alpine sh -lc "pip install -q 'pymodbus==3.6.9' && python /attack.py" 2>&1
    $out = $out | Where-Object { "$_".Trim() -and ($_ -notmatch 'Running pip as the|new release of pip|To update, run|root-user-action|RemoteException') }
    Write-Host ("       " + ($out -join "`n       "))
    if ($out -match "^OK$|(^|\s)OK$") { Write-Ok "Interaccion enviada. Revisa Wazuh: $($ESPERADO['1'].Wazuh)."; return $true }
    Write-Warn "El cliente pymodbus no confirmo OK. Alternativa (libmodbus de tu guia Caso 1):"
    Write-Warn "   modbus -v -s 1 127.0.0.1:502 h@0"
    return $false
}

function Ensure-Zeek{
    # El Caso 2 recrea siempre Zeek para:
    #   - aplicar exactamente la receta validada;
    #   - recalcular su MAC;
    #   - limpiar el estado de conexiones;
    #   - evitar que la supresion de NOTICE de una ejecucion anterior oculte la demo.
    if (-not (Test-Path $CFG.ZeekScriptDir)) {
        Write-Err "La carpeta de scripts Zeek no existe: $($CFG.ZeekScriptDir)."
        return $false
    }
    if (-not (Test-Path $CFG.ZeekLogDir)) {
        New-Item -ItemType Directory -Force $CFG.ZeekLogDir | Out-Null
    }

    $hostScript = Join-Path $CFG.ZeekScriptDir $CFG.ZeekScript
    if (-not (Test-Path $hostScript)) {
        Write-Err "No existe el script principal: $hostScript"
        return $false
    }

    # Advertencia util para repeticiones manuales sin recrear el contenedor.
    $scriptText = Get-Content $hostScript -Raw -ErrorAction SilentlyContinue
    if ($scriptText -notmatch "Notice::not_suppressed_types" -and
        $scriptText -notmatch '\$suppress_for\s*=\s*0secs') {
        Write-Warn "El script no desactiva la supresion de NOTICE."
        Write-Warn "Este orquestador recrea Zeek en cada Caso 2, pero los replays manuales repetidos"
        Write-Warn "pueden quedar suprimidos durante 3600 s."
    }

    Write-Step "Validando $($CFG.ZeekScript) con Zeek 8.2.1 (sin bare mode)..."
    $siteDir = "/opt/zeek/share/zeek/site/tfg"
    $zeekBin = $CFG.ZeekBin
    $scriptMount = "$($CFG.ZeekScriptDir):${siteDir}:ro"
    $validateOut = docker run --rm `
        -v $scriptMount `
        $CFG.ZeekImage `
        $zeekBin -C "$siteDir/$($CFG.ZeekScript)" 2>&1

    if ($LASTEXITCODE -ne 0) {
        Write-Err "El script Zeek no supera la validacion:"
        $validateOut | ForEach-Object { Write-Host "       $_" }
        return $false
    }
    Write-Ok "Script Zeek valido."

    Write-Step "Recreando '$($CFG.ZeekCtr)' con la receta live validada..."
    docker rm -f $CFG.ZeekCtr 2>$null | Out-Null

    # Truncar sin borrar: conserva la ruta/inodo para la monitorizacion compartida.
    if (Test-Path $CFG.ZeekNoticePath) {
        Clear-Content $CFG.ZeekNoticePath -ErrorAction SilentlyContinue
    } else {
        New-Item -ItemType File -Force $CFG.ZeekNoticePath | Out-Null
    }

    $inline = "redef LogAscii::use_json=T; redef Log::flush_interval=100msec; redef tcp_inactivity_timeout=5sec; redef tcp_connection_linger=1sec;"
    $zeekStart = "cd /logs && exec $($CFG.ZeekBin) -C -i $($CFG.Iface) -e '$inline' $siteDir/$($CFG.ZeekScript)"

    $startOut = docker run -d --name $CFG.ZeekCtr `
        --network $CFG.ZeekNet `
        --cap-add=NET_ADMIN `
        --cap-add=NET_RAW `
        -v $scriptMount `
        -v "$($CFG.ZeekLogDir):/logs" `
        $CFG.ZeekImage `
        sh -c $zeekStart 2>&1

    if ($LASTEXITCODE -ne 0) {
        Write-Err "Docker no pudo crear Zeek:"
        $startOut | ForEach-Object { Write-Host "       $_" }
        return $false
    }

    Start-Sleep -Seconds 3
    if (-not (Test-Ctr $CFG.ZeekCtr)) {
        Write-Err "Zeek arranco y se detuvo. Log del contenedor:"
        docker logs $CFG.ZeekCtr 2>&1 |
            Select-Object -Last 40 |
            ForEach-Object { Write-Host "       $_" }
        return $false
    }

    # Recalcular SIEMPRE despues de recrear los contenedores/sensor.
    $script:ZEEKMAC = Get-Mac $CFG.ZeekCtr
    $script:SENDERMAC = Get-Mac $CFG.SenderCtr

    if (-not $script:ZEEKMAC -or -not $script:SENDERMAC) {
        Write-Err "No se pudieron obtener ZEEKMAC/SENDERMAC."
        return $false
    }

    Write-Ok "Zeek live operativo."
    Write-Step "ZEEKMAC   = $script:ZEEKMAC"
    Write-Step "SENDERMAC = $script:SENDERMAC"
    return $true
}

function Test-ZeekNotices{
    param([int]$TimeoutSec = 8)

    if ($NoVerificar) { return $true }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    do {
        Start-Sleep -Milliseconds 500
        if (Test-Path $CFG.ZeekNoticePath) {
            $notices = @(Get-Content $CFG.ZeekNoticePath -Tail 20 -ErrorAction SilentlyContinue |
                Where-Object { $_ -match "UnauthorizedModbusPeer|UnauthorizedWrite|UnauthorizedRead" })
            if ($notices.Count -gt 0) {
                Write-Ok "Zeek genero $($notices.Count) NOTICE Modbus:"
                $notices | ForEach-Object {
                    try {
                        $j = $_ | ConvertFrom-Json
                        Write-Host ("       [{0}] {1}" -f $j.note, $j.msg)
                    } catch {
                        Write-Host "       $_"
                    }
                }
                return $true
            }
        }
    } while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec)

    Write-Err "Zeek recibio el replay, pero notice.log no contiene avisos Modbus nuevos."
    Write-Warn "Revisa los logs live:"
    foreach ($name in @("conn.log","modbus.log","notice.log","weird.log","reporter.log")) {
        $p = Join-Path $CFG.ZeekLogDir $name
        if (Test-Path $p) {
            $fi = Get-Item $p
            Write-Host ("       {0,-14} {1,8} bytes  {2}" -f $name, $fi.Length, $fi.LastWriteTime)
        }
    }
    return $false
}

function Invoke-Caso2{
    Write-Section "Caso 2 - Zeek / ACL Modbus (reinyeccion live)"
    if (-not (Test-Ctr $CFG.SenderCtr)) {
        Write-Err "El contenedor '$($CFG.SenderCtr)' no esta corriendo."
        return $false
    }
    if (-not (Ensure-Zeek)) {
        Write-Warn "No se pudo dejar Zeek operativo; se omite el Caso 2."
        return $false
    }

    Write-Step "PCAP validado: $($CFG.Pcap.Caso2)"
    Write-Step "Velocidad Zeek validada: --pps=$ZeekPps"

    $replayOk = Invoke-Replay `
        -Pcap $CFG.Pcap.Caso2 `
        -SensorMac $script:ZEEKMAC `
        -Pps $ZeekPps

    if (-not $replayOk) { return $false }

    $noticeOk = Test-ZeekNotices
    if ($noticeOk) {
        Write-Ok "Caso 2 completado. Wazuh esperado: reglas 100021 y 100020."
        Write-Step "Manager: tail -n 0 -f /var/ossec/logs/alerts/alerts.json | jq -c 'select((.rule.id|tostring)|test(`"^10002`"))'"
    }
    return $noticeOk
}

function Invoke-Caso3{
    Write-Section "Caso 3 - Movimiento lateral (Suricata, reinyeccion)"
    return (Invoke-Replay -Pcap $CFG.Pcap.Caso3 -SensorMac $script:SURIMAC -Pps $Pps)
}

function Invoke-Caso5b{
    Write-Section "Caso 5b - DPI puerto/protocolo (Suricata, 3 reinyecciones)"
    $ok = $true
    foreach($p in $CFG.Pcap.Caso5b){
        if (-not (Invoke-Replay -Pcap $p -SensorMac $script:SURIMAC -Pps $Pps)) { $ok = $false }
        Start-Sleep -Seconds 2
    }
    if ($ok) { Write-Ok "5b completo. SID esperados: 5500001 / 5500007 / 5500008." }
    return $ok
}

function Invoke-Caso6{
    Write-Section "Caso 6 - Escaneo de activos/servicios (Suricata)"
    return (Invoke-Replay -Pcap $CFG.Pcap.Caso6 -SensorMac $script:SURIMAC -Pps $Pps)
}

function Invoke-Caso7{
    Write-Section "Caso 7 - Fuerza bruta SSH (Suricata)"
    $r = Invoke-Replay -Pcap $CFG.Pcap.Caso7 -SensorMac $script:SURIMAC -Pps $Pps
    Write-Warn "Para la elevacion 100071 (noche): o reinyectas en ventana 20:00-07:00, o amplias <time> de la regla y reviertes."
    return $r
}

function Invoke-Caso4{
    Write-Section "Caso 4 - FIM sobre vsftpd (PUT FTP anonimo real)"
    if (-not (Get-Command curl.exe -ErrorAction SilentlyContinue)) { Write-Err "curl.exe no disponible."; return $false }
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $tmp = Join-Path $env:TEMP "aviso_$stamp.txt"
    "contenido manipulado $stamp" | Set-Content -Encoding ASCII $tmp
    $dest = "ftp://$($CFG.VM2)/$($CFG.FtpDir)/"
    Write-Step "Subiendo $(Split-Path $tmp -Leaf) a $dest (anonymous)"
    curl.exe -s --connect-timeout 8 -T $tmp $dest --user "anonymous:" 2>&1 | Out-Host
    if ($LASTEXITCODE -eq 0) { Write-Ok "PUT realizado. Revisa Integrity monitoring (regla 554)."; return $true }
    Write-Err "curl devolvio $LASTEXITCODE. Comprueba vsftpd en $($CFG.VM2) y permisos de /srv/ftp/$($CFG.FtpDir)."
    return $false
}

function Invoke-Caso5{
    Write-Section "Caso 5 - Acceso SSH fuera de horario (login real)"
    Write-Warn "PRECONDICION horaria: la regla 100030 solo eleva si la hora del evento esta en 20:00-07:00,"
    Write-Warn "  o si has ampliado temporalmente el <time> de la regla en VM1. Esto NO lo hace el script."
    $target = "$($CFG.SshUser)@$($CFG.VM2)"
    $plink = Get-Command plink.exe -ErrorAction SilentlyContinue
    if ($CFG.SshPassword -and $plink) {
        Write-Step "Login no interactivo con plink -> $target"
        & plink.exe -ssh -batch -pw $CFG.SshPassword $target "true" 2>&1 | Out-Host
        $code = $LASTEXITCODE
    } elseif (Get-Command ssh.exe -ErrorAction SilentlyContinue) {
        Write-Step "Login con ssh.exe -> $target (puede pedir contrasena)"
        & ssh.exe -o StrictHostKeyChecking=accept-new -o ConnectTimeout=8 $target "true" | Out-Host
        $code = $LASTEXITCODE
    } else { Write-Err "Ni plink.exe ni ssh.exe disponibles."; return $false }
    if ($code -eq 0) { Write-Ok "Login SSH correcto (genera 'Accepted' en auth.log). Revisa regla 100030."; return $true }
    Write-Err "El login SSH no se completo (codigo $code)."; return $false
}

# =====================================================================================
# VERIFICACION LOCAL (eve.json) PARA CASOS DE RED
# =====================================================================================
function Test-EveSids{
    param([int[]]$Sids)
    if ($NoVerificar -or -not $Sids -or $Sids.Count -eq 0) { return }
    if (-not (Test-Path $CFG.EvePath)) { Write-Warn "eve.json no encontrado en $($CFG.EvePath); omito verificacion."; return }
    Start-Sleep -Seconds 2
    $tail = Get-Content $CFG.EvePath -Tail 400 -ErrorAction SilentlyContinue
    foreach($s in $Sids){
        if ($tail | Select-String "`"signature_id`":$s") { Write-Ok "eve.json: SID $s presente." }
        else { Write-Warn "eve.json: SID $s no visto en las ultimas lineas (puede tardar o requerir --pps menor)." }
    }
}

# =====================================================================================
# DISPATCH
# =====================================================================================
function Invoke-Caso{
    param([string]$id)
    switch ($id) {
        "1"  { $r = Invoke-Caso1 }
        "2"  { $r = Invoke-Caso2 }
        "3"  { $r = Invoke-Caso3;  Test-EveSids $ESPERADO["3"].Sid }
        "5b" { $r = Invoke-Caso5b; Test-EveSids $ESPERADO["5b"].Sid }
        "6"  { $r = Invoke-Caso6;  Test-EveSids $ESPERADO["6"].Sid }
        "7"  { $r = Invoke-Caso7;  Test-EveSids $ESPERADO["7"].Sid }
        "4"  { $r = Invoke-Caso4 }
        "5"  { $r = Invoke-Caso5 }
        default { Write-Err "Caso desconocido: $id"; $r = $false }
    }
    return [pscustomobject]@{ Caso=$id; Plano=$ESPERADO[$id].Plano; Resultado=$(if($r){"OK"}else{"REVISAR"}); Wazuh=$ESPERADO[$id].Wazuh }
}

function Show-Catalogo{
    Write-Section "Catalogo de casos practicos"
    "{0,-4} {1,-6} {2}" -f "Id","Plano","Que dispara" | Write-Host
    "{0,-4} {1,-6} {2}" -f "1","HOST","Cliente Modbus -> Conpot (honeypot)" | Write-Host
    "{0,-4} {1,-6} {2}" -f "2","RED","Replay ataque_modbus.pcap -> Zeek live (ACL Modbus)" | Write-Host
    "{0,-4} {1,-6} {2}" -f "3","RED","Replay movimiento_lateral -> Suricata" | Write-Host
    "{0,-4} {1,-6} {2}" -f "5b","RED","Replay HTTP@502 / SSH@8080 / binario@3389 -> Suricata DPI" | Write-Host
    "{0,-4} {1,-6} {2}" -f "6","RED","Replay escaneo_activos_servicios -> Suricata" | Write-Host
    "{0,-4} {1,-6} {2}" -f "7","RED","Replay ssh_bruteforce_billetaje -> Suricata" | Write-Host
    "{0,-4} {1,-6} {2}" -f "4","HOST","PUT FTP anonimo -> VM2 (FIM)" | Write-Host
    "{0,-4} {1,-6} {2}" -f "5","HOST","Login SSH -> VM2 (fuera de horario)" | Write-Host
}

function Expand-Casos{
    param([string[]]$sel)
    $out = @()
    foreach($s in $sel){
        $t = $s.Trim().ToLower()
        if ($t -eq "all" -or $t -eq "todos") { $out += $ORDEN_ALL }
        elseif ($ESPERADO.ContainsKey($t))   { $out += $t }
        else { Write-Warn "Ignorado token no valido: '$s'" }
    }
    return ($out | Select-Object -Unique)
}

function Invoke-Lote{
    param([string[]]$ids)
    $resultados = @()
    foreach($id in $ids){ $resultados += (Invoke-Caso $id) }
    Write-Section "Resumen"
    $resultados | Format-Table Caso,Plano,Resultado,Wazuh -AutoSize | Out-Host
    Write-Host "Verificacion de alertas en Wazuh Manager (VM1):" -ForegroundColor Cyan
    Write-Host "  tail -f /var/ossec/logs/alerts/alerts.json | jq -c '{id:.rule.id, desc:.rule.description, src:.data.src_ip}'" -ForegroundColor Gray
}

# =====================================================================================
# MAIN
# =====================================================================================
if ($Listar) { Show-Catalogo; return }

if (-not (Invoke-Preflight)) { return }

$objetivo = Expand-Casos $Casos
if (-not $objetivo) { Write-Err "No hay casos validos que ejecutar."; Show-Catalogo; return }

Invoke-Lote $objetivo

# Menu interactivo de repeticion (se omite con -NoMenu)
if (-not $NoMenu) {
    do {
        Write-Host ""
        Write-Host "Repetir: [t] todos  |  [numero/lista ej '6,7' o '5b']  |  [l] listar  |  [s] salir" -ForegroundColor Cyan
        $sel = Read-Host "Opcion"
        switch -Regex ($sel.Trim().ToLower()) {
            '^(s|salir|q)$' { Write-Host "Fin."; return }
            '^(l|listar)$'  { Show-Catalogo }
            '^(t|todos|all)$' { Invoke-Lote $ORDEN_ALL }
            default {
                $ids = Expand-Casos ($sel -split '[,\s]+')
                if ($ids) { Invoke-Lote $ids } else { Write-Warn "Entrada no reconocida." }
            }
        }
    } while ($true)
}
