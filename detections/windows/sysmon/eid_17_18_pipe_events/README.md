# eid 17 18 pipe events

Sysmon Event IDs 17/18 — named pipe created and connected.

**17 rules** — critical 7, high 3, medium 7

> Generated index. Severity and MITRE columns are read from each rule file.

| Rule | Severity | MITRE ATT&CK | File |
| --- | --- | --- | --- |
| CobaltStrike Named Pipe | critical | T1055 | [cobaltstrike_named_pipe.yaml](./cobaltstrike_named_pipe.yaml) |
| HackTool - Credential Dumping Tools Named Pipe Created | critical | T1003.001, T1003.002, T1003.004, T1003.005 | [hacktool_credential_dumping_tools_named_pipe_created.yaml](./hacktool_credential_dumping_tools_named_pipe_created.yaml) |
| HackTool - DiagTrackEoP Default Named Pipe | critical | — | [hacktool_diagtrackeop_default_named_pipe.yaml](./hacktool_diagtrackeop_default_named_pipe.yaml) |
| HackTool - Koh Default Named Pipe | critical | T1528, T1134.001 | [hacktool_koh_default_named_pipe.yaml](./hacktool_koh_default_named_pipe.yaml) |
| Malicious Named Pipe Created | critical | T1055 | [malicious_named_pipe_created.yaml](./malicious_named_pipe_created.yaml) |
| RedSun - Named Pipe Created | critical | T1055, T1685 | [redsun_named_pipe_created.yaml](./redsun_named_pipe_created.yaml) |
| Turla Group Named Pipes | critical | T1106 | [turla_group_named_pipes.yaml](./turla_group_named_pipes.yaml) |
| CobaltStrike Named Pipe Patterns | high | T1055 | [cobaltstrike_named_pipe_patterns.yaml](./cobaltstrike_named_pipe_patterns.yaml) |
| HackTool - CoercedPotato Named Pipe Creation | high | T1055 | [hacktool_coercedpotato_named_pipe_creation.yaml](./hacktool_coercedpotato_named_pipe_creation.yaml) |
| HackTool - EfsPotato Named Pipe Creation | high | T1055 | [hacktool_efspotato_named_pipe_creation.yaml](./hacktool_efspotato_named_pipe_creation.yaml) |
| ADFS Database Named Pipe Connection By Uncommon Tool | medium | T1005 | [adfs_database_named_pipe_connection_by_uncommon_tool.yaml](./adfs_database_named_pipe_connection_by_uncommon_tool.yaml) |
| Alternate PowerShell Hosts Pipe | medium | T1059.001 | [alternate_powershell_hosts_pipe.yaml](./alternate_powershell_hosts_pipe.yaml) |
| PsExec Tool Execution From Suspicious Locations - PipeName | medium | T1569.002 | [psexec_tool_execution_from_suspicious_locations_pipename.yaml](./psexec_tool_execution_from_suspicious_locations_pipename.yaml) |
| PUA - CSExec Default Named Pipe | medium | T1021.002, T1569.002 | [pua_csexec_default_named_pipe.yaml](./pua_csexec_default_named_pipe.yaml) |
| PUA - PAExec Default Named Pipe | medium | T1569.002 | [pua_paexec_default_named_pipe.yaml](./pua_paexec_default_named_pipe.yaml) |
| PUA - RemCom Default Named Pipe | medium | T1021.002, T1569.002 | [pua_remcom_default_named_pipe.yaml](./pua_remcom_default_named_pipe.yaml) |
| WMI Event Consumer Created Named Pipe | medium | T1047 | [wmi_event_consumer_created_named_pipe.yaml](./wmi_event_consumer_created_named_pipe.yaml) |
