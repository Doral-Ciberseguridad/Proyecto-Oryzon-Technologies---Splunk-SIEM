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
# MITRE ATT&CK
# ============================================================

MITRE = {
    22: "T1560.001 — Archive via Utility",
    23: "T1567.002 — Exfiltration to Cloud Storage",
    24: "T1041 — Exfiltration Over C2 Channel",
    25: "T1041 — Exfiltration Over C2 Channel",
}


# ============================================================
# CRITICIDAD
# ============================================================

CRITICIDAD = {
    22: "HIGH",
    23: "MEDIUM",
    24: "HIGH",
    25: "CRITICAL",
}


# ============================================================
# CONSULTAS SPL DE LAS CUATRO REGLAS
# NO MODIFICAR LAS CONSULTAS
# ============================================================

RULES = [
    (
        "Windows Archive Collected Data via Powershell",
        r"""`powershell` EventCode=4104 ScriptBlockText = "*Compress-Archive*"  ScriptBlockText = "*\\Temp\\*"
| fillnull
| stats count min(_time) as firstTime max(_time) as lastTime by dest signature signature_id user_id vendor_product EventID Guid Opcode Name Path ProcessID ScriptBlockId ScriptBlockText
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `windows_archive_collected_data_via_powershell_filter`""",
    ),
    (
        "Windows OneDrive Share Mounted via Net",
        r"""| tstats `security_content_summariesonly`
  count min(_time) as firstTime
        max(_time) as lastTime

from datamodel=Endpoint.Processes where

`process_net`
Processes.process="*use*"
Processes.process="*https://d.docs.live.net*"

by Processes.process Processes.vendor_product Processes.user_id Processes.process_hash
   Processes.parent_process_name Processes.parent_process_exec Processes.action
   Processes.dest Processes.process_current_directory Processes.process_path
   Processes.process_integrity_level Processes.original_file_name Processes.parent_process
   Processes.parent_process_path Processes.parent_process_guid Processes.parent_process_id
   Processes.process_guid Processes.process_id Processes.user Processes.process_name

| `drop_dm_object_name(Processes)`

| `security_content_ctime(firstTime)`

| `security_content_ctime(lastTime)`

| `windows_onedrive_share_mounted_via_net_filter`""",
    ),
    (
        "Windows Exfiltration Over C2 Via Invoke RestMethod",
        r"""`powershell` EventCode=4104 ScriptBlockText = "*Invoke-RestMethod *" AND ScriptBlockText = "* -Uri *" AND ScriptBlockText = "* -Method *" AND ScriptBlockText = "* Post *" AND ScriptBlockText = "* -InFile *"
| fillnull
| stats count min(_time) as firstTime max(_time) as lastTime
   BY dest signature signature_id
      user_id vendor_product EventID
      Guid Opcode Name
      Path ProcessID ScriptBlockId
      ScriptBlockText
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `windows_exfiltration_over_c2_via_invoke_restmethod_filter`""",
    ),
    (
        "Windows Exfiltration Over C2 Via Powershell UploadString",
        r"""`powershell` EventCode=4104 ScriptBlockText = "*Net.webclient*" AND ScriptBlockText = "*.UploadString*"
| fillnull
| stats count min(_time) as firstTime max(_time) as lastTime
   BY dest signature signature_id
      user_id vendor_product EventID
      Guid Opcode Name
      Path ProcessID ScriptBlockId
      ScriptBlockText
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `windows_exfiltration_over_c2_via_powershell_uploadstring_filter`""",
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

        print("Conexión con Splunk establecida correctamente.")
        return service

    except Exception as error:
        print(f"Error al conectar con Splunk: {error}")
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

    if PASSWORD == "INTRODUCE_TU_CONTRASENA":
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

    for index, (rule_title, search) in enumerate(RULES, start=1):

        global_number = index + 21

        name = (
            f"OryzonBiotech - Nº {global_number:02d} - {rule_title}"
        )[:100]

        payload = dict(payload_base)

        payload["description"] = (
            f"MITRE ATT&CK: {MITRE[global_number]}. "
            f"Criticidad: {CRITICIDAD[global_number]}."
        )

        # Nº 22 -> 21:00
        # Nº 23 -> 22:00
        # Nº 24 -> 23:00
        # Nº 25 -> 00:00
        hour = (20 + index) % 24
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