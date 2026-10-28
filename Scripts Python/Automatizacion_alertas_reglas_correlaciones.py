#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import splunklib.client as client


# ============================================================
# CONFIGURACIÓN
# ============================================================

EMAIL = ""
PASSWORD = ""

HOST = "localhost"
PORT = 8089
USERNAME = "admin"
OWNER = "admin"
APP = "search"
SHARING = "user"


# ============================================================
# REGLAS DE CORRELACIÓN
# NO MODIFICAR LAS CONSULTAS SPL
# ============================================================

RULES = [
    (
        "Robo de credenciales del Administrador de Windows (Vault)",
        30,
        r"""| savedsearch "OryzonBiotech - Nº 07 - Windows Password Managers Discovery"
| eval equipo=coalesce(dest,host,Computer), tipo="Discovery", tiempo=coalesce(tonumber(lastTime),_time)
| fields equipo tipo tiempo
| append [
    | savedsearch "OryzonBiotech - Nº 06 - Windows Credentials Access via VaultCli Module"
    | eval equipo=coalesce(dest,host,Computer), tipo="VaultAccess", tiempo=coalesce(tonumber(lastTime),_time)
    | fields equipo tipo tiempo
]
| where isnotnull(equipo) AND isnotnull(tiempo)
| sort 0 equipo tiempo
| streamstats current=f last(tipo) as anterior last(tiempo) as tiempo_anterior by equipo
| where tipo="VaultAccess" AND anterior="Discovery" AND tiempo>=tiempo_anterior AND tiempo-tiempo_anterior<=1800
| eval diferencia_segundos=round(tiempo-tiempo_anterior,0), hora_inicio=strftime(tiempo_anterior,"%Y-%m-%d %H:%M:%S"), hora_acceso=strftime(tiempo,"%Y-%m-%d %H:%M:%S")
| table equipo hora_inicio hora_acceso diferencia_segundos""",
    ),
    (
        "Robo de credenciales y volcado LSASS",
        15,
        r"""| savedsearch "OryzonBiotech - Nº 02 - Kerberoasting SPN Request with RC4 Encryption"
| eval equipo=coalesce(dest,host,Computer), tipo="Kerberoasting", tiempo=coalesce(tonumber(lastTime),_time)
| fields equipo tipo tiempo
| append [
    | savedsearch "OryzonBiotech - Nº 03 - Access LSASS Memory for Dump Creation"
    | eval equipo=coalesce(dest,host,Computer), tipo="LSASS", tiempo=coalesce(tonumber(lastTime),_time)
    | fields equipo tipo tiempo
]
| where isnotnull(equipo) AND isnotnull(tiempo)
| sort 0 equipo tiempo
| streamstats current=f last(tipo) as anterior last(tiempo) as tiempo_anterior by equipo
| where tipo="LSASS" AND anterior="Kerberoasting" AND tiempo>=tiempo_anterior AND tiempo-tiempo_anterior<=900
| eval diferencia_segundos=round(tiempo-tiempo_anterior,0), hora_inicio=strftime(tiempo_anterior,"%Y-%m-%d %H:%M:%S"), hora_lsass=strftime(tiempo,"%Y-%m-%d %H:%M:%S")
| table equipo hora_inicio hora_lsass diferencia_segundos""",
    ),
    (
        "Password spray y acceso remoto",
        30,
        r"""| savedsearch "OryzonBiotech - Nº 01 - Detect Password Spray Attack Behavior From Source"
| eval equipo=coalesce(dest,host,Computer,src), tipo="PasswordSpray", tiempo=coalesce(tonumber(lastTime),_time)
| fields equipo tipo tiempo
| append [
    | savedsearch "OryzonBiotech - Nº 17 - Windows RDP Login Session Was Established"
    | eval equipo=coalesce(dest,host,Computer), tipo="RDP", tiempo=coalesce(tonumber(lastTime),_time)
    | fields equipo tipo tiempo
]
| where isnotnull(equipo) AND isnotnull(tiempo)
| sort 0 equipo tiempo
| streamstats current=f last(tipo) as anterior last(tiempo) as tiempo_anterior by equipo
| where tipo="RDP" AND anterior="PasswordSpray" AND tiempo>=tiempo_anterior AND tiempo-tiempo_anterior<=1800
| eval diferencia_segundos=round(tiempo-tiempo_anterior,0), hora_spray=strftime(tiempo_anterior,"%Y-%m-%d %H:%M:%S"), hora_rdp=strftime(tiempo,"%Y-%m-%d %H:%M:%S")
| table equipo hora_spray hora_rdp diferencia_segundos""",
    ),
    (
        "Volcado de memoria y certificados",
        15,
        r"""| savedsearch "OryzonBiotech - Nº 03 - Access LSASS Memory for Dump Creation"
| eval equipo=coalesce(dest,host,Computer), tipo="LSASS", tiempo=coalesce(tonumber(lastTime),_time)
| fields equipo tipo tiempo
| append [
    | savedsearch "OryzonBiotech - Nº 09 - Windows PowerShell Export Certificate"
    | eval equipo=coalesce(dest,host,Computer), tipo="CertificateExport", tiempo=coalesce(tonumber(lastTime),_time)
    | fields equipo tipo tiempo
]
| where isnotnull(equipo) AND isnotnull(tiempo)
| sort 0 equipo tiempo
| streamstats current=f last(tipo) as anterior last(tiempo) as tiempo_anterior by equipo
| where tipo="CertificateExport" AND anterior="LSASS" AND tiempo>=tiempo_anterior AND tiempo-tiempo_anterior<=900
| eval diferencia_segundos=round(tiempo-tiempo_anterior,0), hora_lsass=strftime(tiempo_anterior,"%Y-%m-%d %H:%M:%S"), hora_certificado=strftime(tiempo,"%Y-%m-%d %H:%M:%S")
| table equipo hora_lsass hora_certificado diferencia_segundos""",
    ),
    (
        "Ejecución inicial mediante ofimática y PowerShell",
        5,
        r"""| savedsearch "OryzonBiotech - Nº 20 - Windows Office Product Spawned Uncommon Process"
| eval equipo=coalesce(dest,host,Computer), tipo="OfficeProcess", tiempo=coalesce(tonumber(lastTime),_time)
| fields equipo tipo tiempo
| append [
    | savedsearch "OryzonBiotech - Nº 14 - PowerShell Environment Variable Execution"
    | eval equipo=coalesce(dest,host,Computer), tipo="PowerShellEnv", tiempo=coalesce(tonumber(lastTime),_time)
    | fields equipo tipo tiempo
]
| where isnotnull(equipo) AND isnotnull(tiempo)
| sort 0 equipo tiempo
| streamstats current=f last(tipo) as anterior last(tiempo) as tiempo_anterior by equipo
| where tipo="PowerShellEnv" AND anterior="OfficeProcess" AND tiempo>=tiempo_anterior AND tiempo-tiempo_anterior<=300
| eval diferencia_segundos=round(tiempo-tiempo_anterior,0), hora_office=strftime(tiempo_anterior,"%Y-%m-%d %H:%M:%S"), hora_powershell=strftime(tiempo,"%Y-%m-%d %H:%M:%S")
| table equipo hora_office hora_powershell diferencia_segundos""",
    ),
    (
        "Escalada de privilegios en Active Directory",
        15,
        r"""| savedsearch "OryzonBiotech - Nº 12 - Windows AD Dangerous User ACL Modification"
| eval equipo=coalesce(dest,host,Computer), tipo="ACLModification", tiempo=coalesce(tonumber(lastTime),_time)
| fields equipo tipo tiempo
| append [
    | savedsearch "OryzonBiotech - Nº 11 - Windows AD User Suspicious UPN Change"
    | eval equipo=coalesce(dest,host,Computer), tipo="UPNChange", tiempo=coalesce(tonumber(lastTime),_time)
    | fields equipo tipo tiempo
]
| where isnotnull(equipo) AND isnotnull(tiempo)
| sort 0 equipo tiempo
| streamstats current=f last(tipo) as anterior last(tiempo) as tiempo_anterior by equipo
| where tipo="UPNChange" AND anterior="ACLModification" AND tiempo>=tiempo_anterior AND tiempo-tiempo_anterior<=900
| eval diferencia_segundos=round(tiempo-tiempo_anterior,0), hora_acl=strftime(tiempo_anterior,"%Y-%m-%d %H:%M:%S"), hora_upn=strftime(tiempo,"%Y-%m-%d %H:%M:%S")
| table equipo hora_acl hora_upn diferencia_segundos""",
    ),
    (
        "Impacto de ransomware y copias de seguridad",
        10,
        r"""| savedsearch "OryzonBiotech - Nº 13 - Creation of Shadow Copy with WMIC and PowerShell"
| eval tipo="ShadowCopy", tiempo=strptime(lastTime,"%Y-%m-%dT%H:%M:%S")
| append [
    | savedsearch "OryzonBiotech - Nº 21 - Ransomware Notes bulk creation"
    | eval tipo="Ransomware", tiempo=strptime(firstTime,"%Y-%m-%dT%H:%M:%S")
]
| sort 0 dest tiempo
| streamstats current=f last(tipo) as anterior last(tiempo) as tiempo_anterior by dest
| where tipo="Ransomware"
    AND anterior="ShadowCopy"
    AND tiempo>=tiempo_anterior
    AND tiempo-tiempo_anterior<=1000
| eval diferencia_segundos=tiempo-tiempo_anterior
| eval hora_shadow=strftime(tiempo_anterior,"%Y-%m-%d %H:%M:%S")
| eval hora_ransomware=strftime(tiempo,"%Y-%m-%d %H:%M:%S")
| table dest hora_shadow hora_ransomware diferencia_segundos""",
    ),
    (
        "Ofimática maliciosa y despliegue de ransomware",
        30,
        r"""| savedsearch "OryzonBiotech - Nº 20 - Windows Office Product Spawned Uncommon Process"
| eval equipo=coalesce(dest,host,Computer), tipo="OfficeProcess", tiempo=coalesce(tonumber(lastTime),_time)
| fields equipo tipo tiempo
| append [
    | savedsearch "OryzonBiotech - Nº 21 - Ransomware Notes bulk creation"
    | eval equipo=coalesce(dest,host,Computer), tipo="RansomwareNotes", tiempo=coalesce(tonumber(firstTime),_time)
    | fields equipo tipo tiempo
]
| where isnotnull(equipo) AND isnotnull(tiempo)
| sort 0 equipo tiempo
| streamstats current=f last(tipo) as anterior last(tiempo) as tiempo_anterior by equipo
| where tipo="RansomwareNotes" AND anterior="OfficeProcess" AND tiempo>=tiempo_anterior AND tiempo-tiempo_anterior<=1800
| eval diferencia_segundos=round(tiempo-tiempo_anterior,0), hora_office=strftime(tiempo_anterior,"%Y-%m-%d %H:%M:%S"), hora_notas=strftime(tiempo,"%Y-%m-%d %H:%M:%S")
| table equipo hora_office hora_notas diferencia_segundos""",
    ),
    (
        "Archivado de datos y extorsión por ransomware",
        30,
        r"""| savedsearch "OryzonBiotech - Nº 22 - Windows Archive Collected Data via Powershell"
| eval equipo=coalesce(dest,host,Computer), tipo="Archive", tiempo=coalesce(tonumber(lastTime),_time)
| fields equipo tipo tiempo
| append [
    | savedsearch "OryzonBiotech - Nº 21 - Ransomware Notes bulk creation"
    | eval equipo=coalesce(dest,host,Computer), tipo="RansomwareNotes", tiempo=coalesce(tonumber(firstTime),_time)
    | fields equipo tipo tiempo
]
| where isnotnull(equipo) AND isnotnull(tiempo)
| sort 0 equipo tiempo
| streamstats current=f last(tipo) as anterior last(tiempo) as tiempo_anterior by equipo
| where tipo="RansomwareNotes" AND anterior="Archive" AND tiempo>=tiempo_anterior AND tiempo-tiempo_anterior<=1800
| eval diferencia_segundos=round(tiempo-tiempo_anterior,0), hora_archivado=strftime(tiempo_anterior,"%Y-%m-%d %H:%M:%S"), hora_notas=strftime(tiempo,"%Y-%m-%d %H:%M:%S")
| table equipo hora_archivado hora_notas diferencia_segundos""",
    ),
    (
        "Persistencia con cuentas y control de accesos",
        10,
        r"""| savedsearch "OryzonBiotech - Nº 10 - Windows Create Local Account"
| eval equipo=coalesce(dest,host,Computer), tipo="LocalAccount", tiempo=coalesce(tonumber(lastTime),_time)
| fields equipo tipo tiempo
| append [
    | savedsearch "OryzonBiotech - Nº 19 - Disabling Remote User Account Control"
    | eval equipo=coalesce(dest,host,Computer), tipo="UACChange", tiempo=coalesce(tonumber(lastTime),_time)
    | fields equipo tipo tiempo
]
| where isnotnull(equipo) AND isnotnull(tiempo)
| sort 0 equipo tiempo
| streamstats current=f last(tipo) as anterior last(tiempo) as tiempo_anterior by equipo
| where tipo="UACChange" AND anterior="LocalAccount" AND tiempo>=tiempo_anterior AND tiempo-tiempo_anterior<=600
| eval diferencia_segundos=round(tiempo-tiempo_anterior,0), hora_cuenta=strftime(tiempo_anterior,"%Y-%m-%d %H:%M:%S"), hora_uac=strftime(tiempo,"%Y-%m-%d %H:%M:%S")
| table equipo hora_cuenta hora_uac diferencia_segundos""",
    ),
    (
        "Creación de cuenta local y persistencia en tareas",
        40,
        r"""| savedsearch "OryzonBiotech - Nº 10 - Windows Create Local Account"
| eval equipo=coalesce(dest,host,Computer), tipo="LocalAccount", tiempo=coalesce(tonumber(lastTime),_time)
| fields equipo tipo tiempo
| append [
    | savedsearch "OryzonBiotech - Nº 15 - Windows Scheduled Task with Suspicious Name"
    | eval equipo=coalesce(dest,host,Computer), tipo="ScheduledTask", tiempo=coalesce(tonumber(lastTime),_time)
    | fields equipo tipo tiempo
]
| where isnotnull(equipo) AND isnotnull(tiempo)
| sort 0 equipo tiempo
| streamstats current=f last(tipo) as anterior last(tiempo) as tiempo_anterior by equipo
| where tipo="ScheduledTask" AND anterior="LocalAccount" AND tiempo>=tiempo_anterior AND tiempo-tiempo_anterior<=2400
| eval diferencia_segundos=round(tiempo-tiempo_anterior,0), hora_cuenta=strftime(tiempo_anterior,"%Y-%m-%d %H:%M:%S"), hora_tarea=strftime(tiempo,"%Y-%m-%d %H:%M:%S")
| table equipo hora_cuenta hora_tarea diferencia_segundos""",
    ),
    (
        "Persistencia mediante tareas y arranque",
        40,
        r"""| savedsearch "OryzonBiotech - Nº 15 - Windows Scheduled Task with Suspicious Name"
| eval tipo="ScheduledTask", equipo=coalesce(Computer,dest,host), tiempo=_time
| append [
    | savedsearch "OryzonBiotech - Nº 16 - Windows Boot or Logon Autostart Execution in Startup Folder"
    | eval tipo="StartupFolder", equipo=coalesce(dest,host), tiempo=strptime(firstTime,"%Y-%m-%dT%H:%M:%S")
]
| sort 0 equipo tiempo
| streamstats current=f last(tipo) as tipo_anterior last(tiempo) as tiempo_anterior by equipo
| where isnotnull(tipo_anterior)
    AND tipo!=tipo_anterior
    AND tiempo>=tiempo_anterior
    AND tiempo-tiempo_anterior<=2400
| eval diferencia_segundos=round(tiempo-tiempo_anterior,0)
| eval hora_evento_anterior=strftime(tiempo_anterior,"%Y-%m-%d %H:%M:%S")
| eval hora_evento_actual=strftime(tiempo,"%Y-%m-%d %H:%M:%S")
| table equipo tipo_anterior hora_evento_anterior tipo hora_evento_actual diferencia_segundos""",
    ),
    (
        "Tareas programadas sospechosas y exfiltración C2",
        20,
        r"""| savedsearch "OryzonBiotech - Nº 15 - Windows Scheduled Task with Suspicious Name"
| eval equipo=coalesce(dest,host,Computer), tipo="ScheduledTask", tiempo=coalesce(tonumber(lastTime),_time)
| fields equipo tipo tiempo
| append [
    | savedsearch "OryzonBiotech - Nº 24 - Windows Exfiltration Over C2 Via Invoke RestMethod"
    | eval equipo=coalesce(dest,host,Computer), tipo="InvokeRestMethod", tiempo=coalesce(tonumber(lastTime),_time)
    | fields equipo tipo tiempo
]
| where isnotnull(equipo) AND isnotnull(tiempo)
| sort 0 equipo tiempo
| streamstats current=f last(tipo) as anterior last(tiempo) as tiempo_anterior by equipo
| where tipo="InvokeRestMethod" AND anterior="ScheduledTask" AND tiempo>=tiempo_anterior AND tiempo-tiempo_anterior<=1200
| eval diferencia_segundos=round(tiempo-tiempo_anterior,0), hora_tarea=strftime(tiempo_anterior,"%Y-%m-%d %H:%M:%S"), hora_exfiltracion=strftime(tiempo,"%Y-%m-%d %H:%M:%S")
| table equipo hora_tarea hora_exfiltracion diferencia_segundos""",
    ),
    (
        "Exfiltración de datos por PowerShell",
        30,
        r"""| savedsearch "OryzonBiotech - Nº 22 - Windows Archive Collected Data via Powershell"
| eval equipo=coalesce(dest,host), tipo="Archive", tiempo=tonumber(lastTime)
| where isnotnull(equipo) AND isnotnull(tiempo)
| append [
    | savedsearch "OryzonBiotech - Nº 24 - Windows Exfiltration Over C2 Via Invoke RestMethod"
    | eval equipo=coalesce(host,dest), tipo="Exfiltration", tiempo=tonumber(lastTime)
    | where isnotnull(equipo) AND isnotnull(tiempo)
]
| append [
    search index=index_agentes_windows EventCode=4104
    | eval texto=coalesce(ScriptBlockText,Message)
    | where like(texto,"%Compress-Archive%") AND like(texto,"%\\Temp\\%")
    | stats min(_time) as tiempo max(_time) as lastTime by host
    | eval equipo=host, tipo="Archive"
    | fields equipo tipo tiempo
    | append [
        search index=index_agentes_windows EventCode=4104
        | eval texto=coalesce(ScriptBlockText,Message)
        | where match(texto,"(?i)Invoke-RestMethod")
            AND match(texto,"(?i)(-Uri\\s+|-Method\\s+|-Body\\s+|-InFile\\s+)")
        | stats min(_time) as tiempo max(_time) as lastTime by host
        | eval equipo=host, tipo="Exfiltration"
        | fields equipo tipo tiempo
    ]
]
| dedup equipo tipo tiempo
| sort 0 equipo tiempo
| streamstats current=f last(tipo) as tipo_anterior last(tiempo) as tiempo_anterior by equipo
| where tipo="Exfiltration"
    AND tipo_anterior="Archive"
    AND tiempo>=tiempo_anterior
    AND tiempo-tiempo_anterior<=1800
| eval diferencia_segundos=round(tiempo-tiempo_anterior,0)
| eval hora_archivado=strftime(tiempo_anterior,"%Y-%m-%d %H:%M:%S")
| eval hora_exfiltracion=strftime(tiempo,"%Y-%m-%d %H:%M:%S")
| table equipo hora_archivado hora_exfiltracion diferencia_segundos""",
    ),
    (
        "Sincronización y exfiltración en la nube",
        40,
        r"""| savedsearch "OryzonBiotech - Nº 23 - Windows OneDrive Share Mounted via Net"
| eval equipo=coalesce(dest,host,Computer), tipo="OneDriveMount", tiempo=coalesce(tonumber(lastTime),_time)
| fields equipo tipo tiempo
| append [
    | savedsearch "OryzonBiotech - Nº 22 - Windows Archive Collected Data via Powershell"
    | eval equipo=coalesce(dest,host,Computer), tipo="Archive", tiempo=coalesce(tonumber(lastTime),_time)
    | fields equipo tipo tiempo
]
| where isnotnull(equipo) AND isnotnull(tiempo)
| sort 0 equipo tiempo
| streamstats current=f last(tipo) as anterior last(tiempo) as tiempo_anterior by equipo
| where tipo="Archive" AND anterior="OneDriveMount" AND tiempo>=tiempo_anterior AND tiempo-tiempo_anterior<=2400
| eval diferencia_segundos=round(tiempo-tiempo_anterior,0), hora_montaje=strftime(tiempo_anterior,"%Y-%m-%d %H:%M:%S"), hora_archivado=strftime(tiempo,"%Y-%m-%d %H:%M:%S")
| table equipo hora_montaje hora_archivado diferencia_segundos""",
    ),
]


# ============================================================
# CONEXIÓN CON SPLUNK
# ============================================================


def connect_to_splunk():
    try:
        service = client.connect(
            host=HOST,
            port=PORT,
            username=USERNAME,
            password=PASSWORD,
            owner=OWNER,
            app=APP,
        )

        print("")
        print("Conexión con Splunk establecida correctamente.")
        print("")
        return service

    except Exception as error:
        print("")
        print(f"Error al conectar con Splunk: {error}")
        print("")
        return None


# ============================================================
# OBTENER UNA ALERTA EXISTENTE
# ============================================================

def get_saved_search(collection, name):
    try:
        return collection[name]
    except KeyError:
        return None


# ============================================================
# CREAR O ACTUALIZAR UNA ALERTA
# ============================================================

def create_or_update_savedsearch(collection, name, search, payload):
    try:
        saved_search = get_saved_search(collection, name)

        if saved_search is not None:
            saved_search.update(search=search, **payload)
            saved_search.refresh()
            print(f"[ACTUALIZADA] {name}")
        else:
            collection.create(name, search=search, **payload)
            print(f"[CREADA] {name}")

        return True

    except Exception as error:
        print(f"[ERROR] {name}: {error}")
        return False


# ============================================================
# PROCESO PRINCIPAL
# ============================================================

def main():

    if EMAIL == "INTRODUCE_TU_CORREO":
        print("Error: configura EMAIL antes de ejecutar el script.")
        return

    if PASSWORD == "INTRODUCE_AQUI_LA_PASSWORD_DE_ADMIN":
        print("Error: configura PASSWORD antes de ejecutar el script.")
        return

    splunk_service = connect_to_splunk()

    if splunk_service is None:
        return

    collection = splunk_service.saved_searches

    payload_base = {
        "is_scheduled": "1",
        "realtime_schedule": "0",
        "disabled": "0",

        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": "0",

        "alert.track": "1",
        "alert.digest_mode": "1",

        "alert.suppress": "1",
        "alert.suppress.period": "60s",

        "action.email": "1",
        "action.email.to": EMAIL,
        "action.email.subject": "Splunk: $name$",
        "actions": "email",

        "dispatch.earliest_time": "-24h",
        "dispatch.latest_time": "now",
    }

    correctas = 0
    fallidas = 0

    for index, (rule_title, intervalo, search) in enumerate(RULES, start=1):

        name = (
            f"Oryzon Biotech - Correlación {index:02d} - {rule_title}"
        )[:100]

        payload = dict(payload_base)

        payload["description"] = (
            f"Correlación de seguridad Oryzon Biotech. "
            f"Intervalo de correlación: {intervalo} minutos."
        )

        # La última alerta actual está programada a las 05:00.
        # Las correlaciones continúan desde las 06:00,
        # una por hora, en orden consecutivo.
        hour = (5 + index) % 24
        payload["cron_schedule"] = f"0 {hour} * * *"

        if create_or_update_savedsearch(
            collection,
            name,
            search,
            payload,
        ):
            correctas += 1
        else:
            fallidas += 1

    print("\nProceso terminado.")
    print(f"Correctas: {correctas}")
    print(f"Fallidas: {fallidas}")
    print(f"Total: {len(RULES)}")


if __name__ == "__main__":
    main()