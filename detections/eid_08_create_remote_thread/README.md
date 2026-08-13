# eid 08 create remote thread

Sysmon Event ID 8 — CreateRemoteThread.

**12 rules** — high 9, medium 3

> Generated index. Severity and MITRE columns are read from each rule file.

| Rule | Severity | MITRE ATT&CK | File |
| --- | --- | --- | --- |
| HackTool - CACTUSTORCH Remote Thread Creation | high | T1055.012, T1059.005, T1059.007, T1218.005 | [hacktool_cactustorch_remote_thread_creation.yaml](./hacktool_cactustorch_remote_thread_creation.yaml) |
| HackTool - Potential CobaltStrike Process Injection | high | T1055.001 | [hacktool_potential_cobaltstrike_process_injection.yaml](./hacktool_potential_cobaltstrike_process_injection.yaml) |
| Password Dumper Remote Thread in LSASS | high | T1003.001 | [password_dumper_remote_thread_in_lsass.yaml](./password_dumper_remote_thread_in_lsass.yaml) |
| Potential Bumblebee Remote Thread Creation | high | T1218.011, T1059.001 | [potential_bumblebee_remote_thread_creation.yaml](./potential_bumblebee_remote_thread_creation.yaml) |
| Potential Credential Dumping Attempt Via PowerShell Remote Thread | high | T1003.001 | [potential_credential_dumping_attempt_via_powershell_remote_thread.yaml](./potential_credential_dumping_attempt_via_powershell_remote_thread.yaml) |
| Rare Remote Thread Creation By Uncommon Source Image | high | T1055 | [rare_remote_thread_creation_by_uncommon_source_image.yaml](./rare_remote_thread_creation_by_uncommon_source_image.yaml) |
| Remote Thread Created In KeePass.EXE | high | T1555.005 | [remote_thread_created_in_keepass_exe.yaml](./remote_thread_created_in_keepass_exe.yaml) |
| Remote Thread Creation In Mstsc.Exe From Suspicious Location | high | — | [remote_thread_creation_in_mstsc_exe_from_suspicious_location.yaml](./remote_thread_creation_in_mstsc_exe_from_suspicious_location.yaml) |
| Remote Thread Creation Ttdinject.exe Proxy | high | T1127 | [remote_thread_creation_ttdinject_exe_proxy.yaml](./remote_thread_creation_ttdinject_exe_proxy.yaml) |
| Remote Thread Creation By Uncommon Source Image | medium | T1055 | [remote_thread_creation_by_uncommon_source_image.yaml](./remote_thread_creation_by_uncommon_source_image.yaml) |
| Remote Thread Creation In Uncommon Target Image | medium | T1055.003 | [remote_thread_creation_in_uncommon_target_image.yaml](./remote_thread_creation_in_uncommon_target_image.yaml) |
| Remote Thread Creation Via PowerShell In Uncommon Target | medium | T1218.011, T1059.001 | [remote_thread_creation_via_powershell_in_uncommon_target.yaml](./remote_thread_creation_via_powershell_in_uncommon_target.yaml) |
