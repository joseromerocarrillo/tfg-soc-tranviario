# Ejecución rápida de los casos prácticos

Esta guía resume el procedimiento mínimo para ejecutar el script principal de reproducción de los casos prácticos del laboratorio.

## 1. Permitir temporalmente la ejecución de scripts

Abrir **Windows PowerShell** y ejecutar:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Este cambio afecta únicamente a la sesión actual de PowerShell y se restablece automáticamente al cerrar la consola.

## 2. Acceder al directorio del proyecto

```powershell
cd C:\tfg
```

## 3. Ejecutar el script principal

```powershell
.\Invoke-CasosPracticos.ps1
```

El script mostrará las opciones disponibles para lanzar los distintos casos prácticos del laboratorio.

## Notas

- Ejecutar los comandos desde **Windows PowerShell**.
- Docker Desktop y las máquinas virtuales necesarias deben estar iniciados antes de lanzar las pruebas.
- Si alguno de los casos no genera la alerta esperada, consultar `TROUBLESHOOTING.md`.
- El cambio realizado con `Set-ExecutionPolicy -Scope Process` no modifica de forma permanente la política de ejecución del sistema.
