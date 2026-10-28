
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


# ============================================================
# REGLAS DE DETECCIÓN
# ============================================================

RULES = [
    {
        "title": "Detect Password Spray Attack Behavior From Source",
        "mitre": "T1110.003",
        "search": r"""
| tstats `security_content_summariesonly` max(_time) as lastTime, min(_time) as firstTime, values(Authentication.user_category) as user_category values(Authentication.src_category) as src_category values(Authentication.app) as app count FROM datamodel=Authentication.Authentication
BY Authentication.action Authentication.app Authentication.authentication_method Authentication.dest Authentication.signature Authentication.signature_id Authentication.src Authentication.user
| `drop_dm_object_name("Authentication")`
| eval user=case(match(upper(user),"[a-zA-Z0-9]{3}"),upper(user),true(),null), src=upper(src), success=if(action="success",count,0),success_user=if(action="success",user,null),failure=if(action="failure",count,0),failed_user=if(action="failure",user,null)
| stats count min(firstTime) as firstTime max(lastTime) as lastTime values(app) as app values(src_category) as src_category values(success_user) as user values(failed_user) as failed_user dc(success_user) as success_dc dc(failed_user) as failed_dc dc(user) as user_dc sum(failure) as failure sum(success) as success BY src
| fields - _time
| where user_dc >= 10 AND .25 > (success/failure) AND failed_dc > success_dc
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `detect_password_spray_attack_behavior_from_source_filter`
"""
    },
    {
        "title": "Kerberoasting SPN Request with RC4 Encryption",
        "mitre": "T1558.003",
        "search": r"""
`wineventlog_security` EventCode=4769 ServiceName!="*$" (TicketOptions=0x40810000 OR TicketOptions=0x40800000 OR TicketOptions=0x40810010) TicketEncryptionType=0x17
| stats count min(_time) as firstTime max(_time) as lastTime BY Computer user service_id service TicketEncryptionType TicketOptions
| rename Computer as dest
| `security_content_ctime(lastTime)`
| `security_content_ctime(firstTime)`
| `kerberoasting_spn_request_with_rc4_encryption_filter`
"""
    },
    {
        "title": "Access LSASS Memory for Dump Creation",
        "mitre": "T1003.001",
        "search": r"""
`sysmon` EventCode=10 TargetImage=*lsass.exe CallTrace=*dbgcore.dll* OR CallTrace=*dbghelp.dll*
| stats count min(_time) as firstTime max(_time) as lastTime BY CallTrace EventID GrantedAccess Guid Opcode ProcessID SecurityID SourceImage SourceProcessGUID SourceProcessId TargetImage TargetProcessGUID TargetProcessId UserID dest granted_access parent_process_exec parent_process_guid parent_process_id parent_process_name parent_process_path process_exec process_guid process_id process_name process_path signature signature_id user_id vendor_product
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `access_lsass_memory_for_dump_creation_filter`
"""
    },
    {
        "title": "Windows AD Replication Request Initiated by User Account",
        "mitre": "T1003.006",
        "search": r"""
`wineventlog_security` EventCode=4662 ObjectType IN ("%{19195a5b-6da0-11d0-afd3-00c04fd930c9}","domainDNS")
AND Properties IN ("*Replicating Directory Changes All*","*Manage Replication Topology*","*Remove Replica In Domain*","*{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}*","*{9923a32a-3607-11d2-b9be-0000f87a36b2}*","*{1131f6ac-9c07-11d1-f79f-00c04fc2dcd2}*")
AND AccessMask="0x100" AND NOT (SubjectUserSid="NT AUT*" OR SubjectUserSid="S-1-5-18" OR SubjectDomainName="Window Manager" OR SubjectUserName="*$")
| stats min(_time) as _time count by SubjectDomainName SubjectUserName Computer Logon_ID ObjectName ObjectServer ObjectType OperationType status dest
| rename SubjectDomainName as Target_Domain SubjectUserName as user Logon_ID as TargetLogonId _time as attack_time
| appendpipe [
    | map search="search `wineventlog_security` EventCode=4624 TargetLogonId=$TargetLogonId$"
    | fields - status
]
| stats min(attack_time) as _time values(TargetUserSid) as TargetUserSid values(Target_Domain) as Target_Domain values(user) as user values(Computer) as Computer values(status) as status values(src_category) as src_category values(src_ip) as src_ip values(action) as action values(authentication_method) as authentication_method values(dest) as dest values(signature) as signature values(signature_id) as signature_id by TargetLogonId
| `windows_ad_replication_request_initiated_by_user_account_filter`
"""
    },
    {
        "title": "Windows Credentials from Web Browsers Saved in TEMP Folder",
        "mitre": "T1555.003",
        "search": r"""
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("login*", "pass*","cookie*","master_key*") Filesystem.file_path="*\\temp\\*" by Filesystem.action Filesystem.dest Filesystem.file_access_time Filesystem.file_create_time Filesystem.file_hash Filesystem.file_modify_time Filesystem.file_name Filesystem.file_path Filesystem.file_acl Filesystem.file_size Filesystem.process_guid Filesystem.process_id Filesystem.user Filesystem.vendor_product
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `windows_credentials_from_web_browsers_saved_in_temp_folder_filter`
"""
    },
    {
        "title": "Windows Credentials Access via VaultCli Module",
        "mitre": "T1555.004",
        "search": r"""
`sysmon` EventCode=7 ImageLoaded="*\\vaultcli.dll" process_path IN("*\\windows\\fonts\\*", "*\\windows\\temp\\*", "*\\users\\public\\*", "*\\windows\\debug\\*", "*\\Users\\Administrator\\Music\\*", "*\\Windows\\servicing\\*", "*\\Users\\Default\\*", "*Recycle.bin*", "*\\Windows\\Media\\*", "\\Windows\\repair\\*", "*\\appdata\\local\\temp\\*", "*\\PerfLogs\\*", "*:\\temp\\*")
| fillnull
| stats count min(_time) as firstTime max(_time) as lastTime by Image ImageLoaded dest loaded_file loaded_file_path original_file_name process_exec process_guid process_hash process_id process_name process_path service_dll_signature_exists service_dll_signature_verified signature signature_id user_id vendor_product
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `windows_credentials_access_via_vaultcli_module_filter`
"""
    },
    {
        "title": "Windows Password Managers Discovery",
        "mitre": "T1555.005",
        "search": r"""
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes
WHERE Processes.process="*dir *"
OR Processes.process="*findstr*"
AND Processes.process IN ("*.kdbx*", "*credential*", "*key3.db*","*pass*", "*cred*", "*key4.db*", "*accessTokens*", "*access_tokens*", "*.htpasswd*", "*Ntds.dit*")
BY Processes.action Processes.dest Processes.original_file_name Processes.parent_process Processes.parent_process_exec Processes.parent_process_guid Processes.parent_process_id Processes.parent_process_name Processes.parent_process_path Processes.process Processes.process_exec Processes.process_guid Processes.process_hash Processes.process_id Processes.process_integrity_level Processes.process_name Processes.process_path Processes.user Processes.user_id Processes.vendor_product
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `windows_password_managers_discovery_filter`
"""
    },
    {
        "title": "Windows Credentials in Registry Reg Query",
        "mitre": "T1552.002",
        "search": r"""
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_reg` AND Processes.process="* query *" AND Processes.process IN ("*\\Software\\ORL\\WinVNC3\\Password*", "*\\SOFTWARE\\RealVNC\\WinVNC4 /v password*", "*\\CurrentControlSet\\Services\\SNMP*", "*\\Software\\TightVNC\\Server*", "*\\Software\\SimonTatham\\PuTTY\\Sessions*", "*\\Software\\OpenSSH\\Agent\\Keys*", "*password*") by Processes.action Processes.dest Processes.original_file_name Processes.parent_process Processes.parent_process_exec Processes.parent_process_guid Processes.parent_process_id Processes.parent_process_name Processes.parent_process_path Processes.process Processes.process_exec Processes.process_guid Processes.process_hash Processes.process_id Processes.process_integrity_level Processes.process_name Processes.process_path Processes.user Processes.user_id Processes.vendor_product
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `windows_credentials_in_registry_reg_query_filter`
"""
    },
    {
        "title": "Windows PowerShell Export Certificate",
        "mitre": "T1649",
        "search": r"""
`powershell` EventCode=4104 ScriptBlockText IN ("*export-certificate*")
| rename Computer as dest
| fillnull
| stats count min(_time) as firstTime max(_time) as lastTime BY dest signature signature_id user_id vendor_product EventID Guid Opcode Name Path ProcessID ScriptBlockId ScriptBlockText
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `windows_powershell_export_certificate_filter`
"""
    },
    {
        "title": "Windows Create Local Account",
        "mitre": "T1136.001",
        "search": r"""
| tstats `security_content_summariesonly` values(All_Changes.result_id) as result_id count min(_time) as firstTime max(_time) as lastTime from datamodel=Change where All_Changes.result_id=4720 by All_Changes.user All_Changes.dest All_Changes.result All_Changes.action
| `drop_dm_object_name("All_Changes")`
| `security_content_ctime(lastTime)`
| `security_content_ctime(firstTime)`
| `windows_create_local_account_filter`
"""
    },
    {
        "title": "Windows AD User Suspicious UPN Change",
        "mitre": "T1098",
        "search": r"""
`wineventlog_security` EventCode=4738 UserPrincipalName="*"
NOT UserPrincipalName IN ("-", "", "*@*", "%%1793")
NOT SubjectUserSid IN ("S-1-5-18", "S-1-5-7")
NOT SubjectUserName IN ("ANONYMOUS*", "NT AUTHORITY*")
| where SubjectUserSid=TargetSid
| stats count min(_time) as firstTime max(_time) as lastTime by dest SubjectUserName SubjectUserSid TargetUserName TargetSid UserPrincipalName
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `windows_ad_user_suspicious_upn_change_filter`
"""
    },
    {
        "title": "Windows AD Dangerous User ACL Modification",
        "mitre": "T1098",
        "search": r"""
`wineventlog_security` EventCode=5136 ObjectClass=user
| stats min(_time) as _time values(eval(if(OperationType=="%%14675",AttributeValue,null))) as old_value values(eval(if(OperationType=="%%14674",AttributeValue,null))) as new_value values(OperationType) as OperationType values(dest) as dest by ObjectClass ObjectDN OpCorrelationID src_user SubjectLogonId
| rex field=old_value max_match=10000 "\((?P<old_values>.*?)\)"
| rex field=new_value max_match=10000 "\((?P<new_ace>.*?)\)"
| mvexpand new_ace
| where NOT new_ace IN (old_values)
| rex field=new_ace "(?P<aceType>.*?);(?P<aceFlags>.*?);(?P<aceAccessRights>.*?);(?P<aceObjectGuid>.*?);(?P<aceInheritedTypeGuid>.*?);(?P<aceSid>.*?)$"
| rex max_match=100 field=aceAccessRights "(?P<AccessRights>[A-Z]{2})"
| rex max_match=100 field=aceFlags "(?P<aceFlags>[A-Z]{2})"
| lookup local=t msad_guid_lookup guid as aceObjectGuid OUTPUT displayName as ControlAccessRights
| lookup local=t ace_access_rights_lookup access_rights_string as AccessRights OUTPUT access_rights_value
| lookup local=t ace_type_lookup ace_type_string as aceType OUTPUT ace_type_value as aceType
| lookup local=t ace_flag_lookup flag_string as aceFlags OUTPUT flag_value as ace_flag_value
| lookup local=t identity_lookup_expanded objectSid as aceSid OUTPUT downLevelDomainName as user
| lookup local=t admon_groups_def objectSid as aceSid OUTPUT cn as group
| lookup local=t builtin_groups_lookup builtin_group_string as aceSid OUTPUT builtin_group_name as builtin_group
| eval aceType=coalesce(ace_type_value,aceType), aceFlags=coalesce(ace_flag_value,"This object only"), aceAccessRights=if(aceAccessRights="CCDCLCSWRPWPDTLOCRSDRCWDWO","Full control",coalesce(access_rights_value,AccessRights)), aceControlAccessRights=coalesce(ControlAccessRights,aceObjectGuid), user=coalesce(user,group,builtin_group,aceSid)
| stats values(aceType) as aceType values(aceFlags) as aceFlags values(aceControlAccessRights) as aceControlAccessRights values(aceAccessRights) as aceAccessRights values(new_ace) as new_ace values(aceInheritedTypeGuid) as aceInheritedTypeGuid by _time ObjectClass ObjectDN src_user SubjectLogonId user OpCorrelationID
| eval aceControlAccessRights=if(mvcount(aceControlAccessRights)=1 AND aceControlAccessRights="","All rights",'aceControlAccessRights')
| search NOT aceType IN (*denied*,D,OD,XD) AND aceAccessRights IN ("Full control","All extended rights","All validated writes","Create all child objects","Delete all child objects","Delete subtree","Delete","Modify permissions","Modify owner","Write all properties",CC,CR,DC,DT,SD,SW,WD,WO,WP)
| `windows_ad_dangerous_user_acl_modification_filter`
"""
    }
]


# ============================================================
# CONEXIÓN A SPLUNK
# ============================================================

def connect_to_splunk():
    service = client.connect(
        host=HOST,
        port=PORT,
        username=USERNAME,
        password=PASSWORD,
        owner=OWNER,
        app=APP
    )

    print("Conexión al servidor exitosa")
    return service


# ============================================================
# CREAR O ACTUALIZAR ALERTAS
# ============================================================

def create_or_update_alert(service, rule, number):
    title = rule["title"]
    search = rule["search"].strip()
    name = f"OryzonBiotech - Nº {number:02d} - {title}"

    # Una ejecución diaria por regla, escalonada entre las 00:00 y las 11:00.
    cron_schedule = f"0 {number - 1} * * *"

    payload = {
        "is_scheduled": "1",
        "cron_schedule": cron_schedule,
        "dispatch.earliest_time": "-24h",
        "dispatch.latest_time": "now",
        "alert_type": "always",
        "alert.track": "1",
        "description": (
            f"Regla de detección {number:02d}: {title}. "
            f"MITRE ATT&CK: {rule['mitre']}"
        ),
        "disabled": "0"
    }

    if EMAIL:
        payload.update({
            "actions": "email",
            "action.email": "1",
            "action.email.to": EMAIL,
            "action.email.subject": f"Alerta de seguridad: {title}",
            "action.email.message": (
                f"Splunk ha generado resultados para la regla: {title}. "
                f"MITRE ATT&CK: {rule['mitre']}"
            ),
            "action.email.sendresults": "1"
        })

    saved_searches = service.saved_searches

    # Compruebo si ya existe una alerta con el nombre exacto.
    existing = None
    for saved_search in saved_searches:
        if saved_search.name == name:
            existing = saved_search
            break

    if existing is not None:
        existing.update(search=search, **payload)
        print(f"[{number:02d}/12] ACTUALIZADA: {name}")
    else:
        saved_searches.create(name, search, **payload)
        print(f"[{number:02d}/12] CREADA: {name}")


# ============================================================
# EJECUCIÓN PRINCIPAL
# ============================================================

def main():
    if not PASSWORD or PASSWORD == "TU_CONTRASEÑA_DE_SPLUNK":
        raise SystemExit(
            "ERROR: introduce tu contraseña de Splunk en PASSWORD "
            "al principio del script."
        )

    service = connect_to_splunk()

    correctas = 0
    fallidas = 0

    for number, rule in enumerate(RULES, start=1):
        try:
            create_or_update_alert(service, rule, number)
            correctas += 1
        except Exception as error:
            fallidas += 1
            print(
                f"[{number:02d}/12] ERROR en "
                f"'{rule['title']}': {error}"
            )

    print("\n" + "=" * 55)
    print("PROCESO TERMINADO")
    print(f"Correctas: {correctas}")
    print(f"Fallidas:  {fallidas}")
    print(f"Total:     {len(RULES)}")
    print("=" * 55)


if __name__ == "__main__":
    main()