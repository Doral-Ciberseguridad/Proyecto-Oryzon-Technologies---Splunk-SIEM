#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import splunklib.client as client


# Configuración de conexión
EMAIL = ""
PASSWORD = ""
HOST = "localhost"
PORT = 8089
USERNAME = "admin"
OWNER = "admin"
APP = "search"
SHARING = "user"


# Referencias MITRE ATT&CK: claves internas del 1 al 9
MITRE = {
    1: "T1003.003 — NTDS (Credential Access)",
    2: "T1059.001 — PowerShell (Execution)",
    3: "T1053.005 — Scheduled Task (Persistence)",
    4: "T1547.001 — Registry Run Keys / Startup Folder (Persistence)",
    5: "T1021.001 — Remote Desktop Protocol (Lateral Movement)",
    6: "T1021.006 — Windows Remote Management (Lateral Movement)",
    7: "T1548.002 — Bypass User Account Control (Privilege Escalation)",
    8: "T1566.001 — Spearphishing Attachment (Initial Access)",
    9: "T1486 — Data Encrypted for Impact (Impact)",
}


# Criticidad acordada
CRITICIDAD = {
    1: "HIGH",
    2: "HIGH",
    3: "HIGH",
    4: "HIGH",
    5: "HIGH",
    6: "HIGH",
    7: "CRITICAL",
    8: "CRITICAL",
    9: "CRITICAL",
}


# Consultas SPL de las nueve reglas
RULES = [
    (
        "Creation of Shadow Copy with WMIC and PowerShell",
        r"""| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes
  WHERE `process_wmic`
    OR
    `process_powershell` Processes.process=*shadowcopy* Processes.process=*create*
  BY Processes.action Processes.dest Processes.original_file_name
     Processes.parent_process Processes.parent_process_exec Processes.parent_process_guid
     Processes.parent_process_id Processes.parent_process_name Processes.parent_process_path
     Processes.process Processes.process_exec Processes.process_guid
     Processes.process_hash Processes.process_id Processes.process_integrity_level
     Processes.process_name Processes.process_path Processes.user
     Processes.user_id Processes.vendor_product
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `creation_of_shadow_copy_with_wmic_and_powershell_filter`""",
    ),
    (
        "PowerShell Environment Variable Execution",
        r"""`powershell`
EventCode=4104
ScriptBlockText="*$env:*"
ScriptBlockText IN (
    "*.Invoke()*",
    "*[scriptblock]::Create*",
    "*iex *",
    "*Invoke-Expression*"
)
ScriptBlockText="*[Environment]::SetEnvironmentVariable*"
| regex ScriptBlockText="(?i)((invoke-expression
|iex\s+
|\biex\b).*\$env:
|\[scriptblock\]::create\s*\(\s*\$env:[^)]+\)\s*(?:\.\s*invoke\s*\(\s*\))?)"
| fillnull
| stats count min(_time) as firstTime
              max(_time) as lastTime
  by dest signature signature_id user_id
     vendor_product EventID Guid
     Opcode Name Path ProcessID
     ScriptBlockId ScriptBlockText
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `powershell_environment_variable_execution_filter`""",
    ),
    (
        "Windows Scheduled Task with Suspicious Name",
        r"""`wineventlog_security` EventCode IN (4698,4700,4702)
| eval TaskContent = case(isnotnull(TaskContentNew),TaskContentNew,true(),TaskContent)
| xmlkv TaskContent
| stats count min(_time) as firstTime max(_time) as lastTime latest(Arguments) as Arguments latest(Author) as Author by Computer, TaskName, Command, Enabled, Hidden,Caller_User_Name, EventCode
| lookup local=t windows_suspicious_tasks task_name as TaskName
| where isnotnull(tool_type)
| eval command=TaskName, process=Command+if(isnotnull(Arguments)," ".Arguments,""), src_user=Author, user = Caller_User_Name, dest = Computer
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `windows_scheduled_task_with_suspicious_name_filter`""",
    ),
    (
        "Windows Boot or Logon Autostart Execution in Startup Folder",
        r"""|tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path = "*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*" by Filesystem.action Filesystem.dest Filesystem.file_access_time Filesystem.file_create_time Filesystem.file_hash Filesystem.file_modify_time Filesystem.file_name Filesystem.file_path Filesystem.file_acl Filesystem.file_size Filesystem.process_guid Filesystem.process_id Filesystem.user Filesystem.vendor_product
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `windows_boot_or_logon_autostart_execution_in_startup_folder_filter`""",
    ),
    (
        "Windows RDP Login Session Was Established",
        r"""`wineventlog_security`  EventCode=4624 Logon_Type=10
| stats count min(_time) as firstTime max(_time) as lastTime
    BY action app authentication_method
       dest dvc process
       process_id process_name process_path
       signature signature_id src
       src_port status subject
       user user_group vendor_product
       Logon_Type
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `windows_rdp_login_session_was_established_filter`""",
    ),
    (
        "Windows Remote Host Computer Management Access",
        r"""| tstats `security_content_summariesonly` min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes
  WHERE Processes.process_name="mmc.exe"
    AND
    Processes.process = "*compmgmt.msc *"
    AND
    Processes.process = "*/computer:*"
  BY Processes.action Processes.dest Processes.original_file_name
     Processes.parent_process Processes.parent_process_exec Processes.parent_process_guid
     Processes.parent_process_id Processes.parent_process_name Processes.parent_process_path
     Processes.process Processes.process_exec Processes.process_guid
     Processes.process_hash Processes.process_id Processes.process_integrity_level
     Processes.process_name Processes.process_path Processes.user
     Processes.user_id Processes.vendor_product
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `windows_remote_host_computer_management_access_filter`""",
    ),
    (
        "Disabling Remote User Account Control",
        r"""| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Registry where Registry.registry_path=*\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA* Registry.registry_value_data="0x00000000" by Registry.action Registry.dest Registry.process_guid Registry.process_id Registry.registry_hive Registry.registry_path Registry.registry_key_name Registry.registry_value_data Registry.registry_value_name Registry.registry_value_type Registry.status Registry.user Registry.vendor_product
| `drop_dm_object_name(Registry)`
| `disabling_remote_user_account_control_filter`""",
    ),
    (
        "Windows Office Product Spawned Uncommon Process",
        r"""| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time)
as lastTime from datamodel=Endpoint.Processes where
`process_office_products_parent`
AND
(
  Processes.process_name IN (
    bitsadmin.exe,
    certutil.exe,
    cmd.exe,
    cscript.exe,
    mshta.exe,
    powershell.exe,
    pwsh.exe,
    regsvr32.exe,
    rundll32.exe,
    wmic.exe,
    wscript.exe
  )
  OR
  Processes.original_file_name IN (
    bitsadmin.exe,
    CertUtil.exe,
    Cmd.Exe,
    cscript.exe,
    MSHTA.EXE,
    PowerShell.EXE,
    pwsh.dll,
    REGSVR32.EXE,
    RUNDLL32.EXE,
    wmic.exe,
    wscript.exe
  )
)
by Processes.action Processes.dest Processes.original_file_name
   Processes.parent_process Processes.parent_process_exec Processes.parent_process_guid
   Processes.parent_process_id Processes.parent_process_name Processes.parent_process_path
   Processes.process Processes.process_exec Processes.process_guid Processes.process_hash
   Processes.process_id Processes.process_integrity_level Processes.process_name Processes.process_path
   Processes.user Processes.user_id Processes.vendor_product
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `windows_office_product_spawned_uncommon_process_filter`""",
    ),
    (
        "Ransomware Notes bulk creation",
        r"""`sysmon` EventCode=11 file_name IN ("*\\.txt","*\\.html","*\\.hta")
| bin _time span=10s
| stats min(_time) as firstTime max(_time) as lastTime dc(TargetFilename) as unique_readme_path_count values(TargetFilename) as list_of_readme_path values(action) as action values(file_access_time) as file_access_time values(file_create_time) as file_create_time values(file_hash) as file_hash values(file_modify_time) as file_modify_time values(file_path) as file_path values(file_acl) as file_acl values(file_size) as file_size values(process_guid) as process_guid values(process_id) as process_id values(user) as user values(vendor_product) as vendor_product
    BY dest file_name
| where unique_readme_path_count >= 15
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `ransomware_notes_bulk_creation_filter`""",
    ),
]



def connect_to_splunk(username, password):
    """Conecta con Splunk mediante la API REST."""
    try:
        service = client.connect(
            host=HOST,
            port=PORT,
            username=username,
            password=password,
            owner=OWNER,
            app=APP,
            sharing=SHARING,
        )
        print("Conexión con Splunk establecida correctamente.")
        return service
    except Exception as error:
        print(f"Error al conectar con Splunk: {error}")
        return None


def get_saved_search(collection, name):
    """Devuelve una alerta existente o None si no existe."""
    try:
        return collection[name]
    except KeyError:
        return None


def create_or_update_savedsearch(collection, name, search, payload):
    """Crea una alerta nueva o actualiza la que ya tenga ese nombre."""
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


def delete_old_savedsearch(collection, old_name):
    """Elimina la alerta antigua solo después de crear/actualizar la nueva."""
    try:
        old_saved_search = get_saved_search(collection, old_name)

        if old_saved_search is not None:
            old_saved_search.delete()
            print(f"[ELIMINADA ANTIGUA] {old_name}")

    except Exception as error:
        print(f"[AVISO] No se pudo eliminar {old_name}: {error}")


def main():
    if PASSWORD == "INTRODUCE_TU_CONTRASENA":
        raise SystemExit(
            "Introduce la contraseña actual de admin en PASSWORD antes de ejecutar."
        )

    if EMAIL == "INTRODUCE_TU_CORREO":
        raise SystemExit("Introduce tu correo en EMAIL antes de ejecutar.")

    splunk_service = connect_to_splunk(USERNAME, PASSWORD)

    if splunk_service is None:
        raise SystemExit("No se pudo conectar con Splunk; no se procesaron alertas.")

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
        # Numeración global: categoría 1 = 01–12; categoría 2 = 13–21.
        global_number = index + 12

        old_name = f"OryzonBiotech - Nº {index:02d} - {rule_title}"[:100]
        new_name = f"OryzonBiotech - Nº {global_number:02d} - {rule_title}"[:100]

        payload = dict(payload_base)
        payload["description"] = (
            f"MITRE ATT&CK: {MITRE[index]}. "
            f"Criticidad: {CRITICIDAD[index]}."
        )

        # Regla global 13 a las 12:00; regla global 21 a las 20:00.
        payload["cron_schedule"] = f"0 {11 + index} * * *"

        # Crear/actualizar la nueva alerta antes de borrar la antigua.
        if create_or_update_savedsearch(
            collection, new_name, search.strip(), payload
        ):
            correctas += 1

            # Evita borrar la nueva alerta si los nombres coincidieran.
            if old_name != new_name:
                delete_old_savedsearch(collection, old_name)
        else:
            fallidas += 1

    print(
        "\nProceso terminado. "
        f"Correctas: {correctas}; fallidas: {fallidas}; "
        f"total: {len(RULES)}"
    )
    print("\nComprueba las alertas en:")
    print(
        "Splunk Server > Search & Reporting > Settings > "
        "Searches, Reports, and Alerts"
    )


if __name__ == "__main__":
    main()