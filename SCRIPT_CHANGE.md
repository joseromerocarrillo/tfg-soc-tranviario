# Cambio aplicado al script

La única modificación realizada a `Invoke-CasosPracticos.ps1` para integrarlo con el repositorio es la ampliación de `ComposeSearchDirs`.

Antes, el script buscaba el Compose en:

```text
$PSScriptRoot
C:\tfg
C:\tfg\docker
C:\tfg\lab
```

Ahora también busca en:

```text
raíz del repositorio
raíz-del-repositorio\docker
```

No se ha cambiado la lógica de ejecución de ningún caso, los PCAP, las reglas esperadas, las IP, los comandos de ataque ni la receta Zeek.
