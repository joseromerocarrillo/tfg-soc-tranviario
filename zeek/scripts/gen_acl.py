# -*- coding: utf-8 -*-
"""Genera modbus_acl.zeek (diccionario unico) desde LISTADO_IPS_PEM.xlsx.
Lectura: toda IP del listado, por su tabla. Escritura: registros de mando en los
equipos comandables (anillo/feeder/grupo/secc) segun la taxonomia del PEM."""
import openpyxl, sys
PEM = sys.argv[1] if len(sys.argv)>1 else "LISTADO_IPS_PEM.xlsx"
wb = openpyxl.load_workbook(PEM, data_only=True)

SUBEST = {"SUBESTACIÓN 2","SUBESTACIÓN 3","SUBESTACIÓN 4","SET 132kV"}
# equipos comandables (escriben ordenes); el resto es solo lectura
def is_cmd(eq): 
    e=eq.upper()
    return any(k in e for k in ("ANILLO","FEEDER","GRUPO","SECC"))
CMD_REGS  = [324,325,326]          # ORDEN disyuntor/desbloqueo/seccionador (PEM senales)
SET_REGS  = [103,324]              # cambiador de tomas + orden (SET 132kV)
CLOCK     = [60,61,62,63,64,65]    # sincronizacion horaria

reads=[]   # (ip, tabla)
writes=[]  # (ip, reg, comentario)
for ws in wb.worksheets:
    title=ws.title
    for r in range(3, ws.max_row+1):
        ip=ws.cell(row=r,column=1).value; eq=ws.cell(row=r,column=2).value
        if not ip: continue
        ip=str(ip).strip(); eq=str(eq or "").strip()
        if title in SUBEST:
            reads.append((ip,"holding",eq))
            if title=="SET 132kV":
                for rg in SET_REGS+CLOCK: writes.append((ip,rg,eq))
            elif is_cmd(eq):
                for rg in CMD_REGS+CLOCK: writes.append((ip,rg,eq))
        elif title=="CIT":
            reads.append((ip,"discrete",eq)); reads.append((ip,"coil",eq))
        elif title=="PARADAS":
            reads.append((ip,"coil",eq))

# IPs vistas en trafico pero no en el listado (a confirmar)
OBSERVED_ONLY=[("192.168.12.20","holding"),("192.168.12.30","holding"),("192.168.12.40","holding")]

L=[]
L.append("##! modbus_acl.zeek - DICCIONARIO UNICO de acceso Modbus (generado del")
L.append("##! LISTADO_IPS_PEM). Lectura: toda IP documentada por su tabla. Escritura:")
L.append("##! registros de mando en equipos comandables (anillo/feeder/grupo/secc).")
L.append("##! Regenerar:  python3 gen_acl.py LISTADO_IPS_PEM.xlsx > modbus_acl.zeek")
L.append("")
L.append("@load ./modbus_whitelist")
L.append("module ModbusACL;")
L.append("")
L.append("# --- LECTURA (Capa 2): (IP, tabla) que cada equipo expone ---")
L.append("redef ModbusWhitelist::read_exposed += {")
cur=None
for ip,tbl,eq in reads:
    if eq!=cur: L.append(f"    # {eq}"); cur=eq
    L.append(f'    [{ip}, "{tbl}"],')
L.append("    # IPs vistas en el trafico pero NO en el listado PEM (confirmar equipo):")
for ip,tbl in OBSERVED_ONLY:
    L.append(f'    [{ip}, "{tbl}"],   # observado, no documentado')
L.append("};")
L.append("")
L.append("# --- ESCRITURA (Capa 3): registros de mando por equipo comandable ---")
L.append("# Supuesto: los equipos comandables comparten el mapa de registros de ORDEN")
L.append("# del PEM de senales (324/325/326) + reloj (60-65); SET usa 103/324. Confirmar")
L.append("# con las senales por equipo si se dispone de ellas.")
L.append("redef ModbusWhitelist::acl += {")
cur=None
for ip,rg,eq in writes:
    if eq!=cur: L.append(f"    # {eq}"); cur=eq
    L.append(f'    [{ip}, "holding", {rg}] = [$rd=T, $wr=T],')
L.append("};")
out="\n".join(L)+"\n"
open("/mnt/user-data/outputs/modbus_acl.zeek","w").write(out)
print("read_exposed:",len(reads)+len(OBSERVED_ONLY),"| write entries:",len(writes))
print("equipos comandables:",len(set(ip for ip,_,_ in writes)))
