# defender operational

Microsoft Defender **Operational** channel — malware verdicts, exclusions and protection state changes.

**15 rules** — critical 1, high 12, medium 2

> Generated index. Severity and MITRE columns are read from each rule file.

| Rule | Severity | MITRE ATT&CK | File |
| --- | --- | --- | --- |
| RedSun - TieringEngineService.exe Detected as EICAR Test File | critical | T1036.005, T1685, T1055 | [redsun_tieringengineservice_exe_detected_as_eicar_test_file.yaml](./redsun_tieringengineservice_exe_detected_as_eicar_test_file.yaml) |
| LSASS Access Detected via Attack Surface Reduction | high | T1003.001 | [lsass_access_detected_via_attack_surface_reduction.yaml](./lsass_access_detected_via_attack_surface_reduction.yaml) |
| Microsoft Defender Tamper Protection Trigger | high | T1685 | [microsoft_defender_tamper_protection_trigger.yaml](./microsoft_defender_tamper_protection_trigger.yaml) |
| PSExec and WMI Process Creations Block | high | T1047, T1569.002 | [psexec_and_wmi_process_creations_block.yaml](./psexec_and_wmi_process_creations_block.yaml) |
| Win Defender Restored Quarantine File | high | T1685 | [win_defender_restored_quarantine_file.yaml](./win_defender_restored_quarantine_file.yaml) |
| Windows Defender AMSI Trigger Detected | high | T1059 | [windows_defender_amsi_trigger_detected.yaml](./windows_defender_amsi_trigger_detected.yaml) |
| Windows Defender Configuration Changes | high | T1685 | [windows_defender_configuration_changes.yaml](./windows_defender_configuration_changes.yaml) |
| Windows Defender Exploit Guard Tamper | high | T1685 | [windows_defender_exploit_guard_tamper.yaml](./windows_defender_exploit_guard_tamper.yaml) |
| Windows Defender Grace Period Expired | high | T1685 | [windows_defender_grace_period_expired.yaml](./windows_defender_grace_period_expired.yaml) |
| Windows Defender Malware And PUA Scanning Disabled | high | T1685 | [windows_defender_malware_and_pua_scanning_disabled.yaml](./windows_defender_malware_and_pua_scanning_disabled.yaml) |
| Windows Defender Real-time Protection Disabled | high | T1685 | [windows_defender_real_time_protection_disabled.yaml](./windows_defender_real_time_protection_disabled.yaml) |
| Windows Defender Threat Detected | high | T1059 | [windows_defender_threat_detected.yaml](./windows_defender_threat_detected.yaml) |
| Windows Defender Virus Scanning Feature Disabled | high | T1685 | [windows_defender_virus_scanning_feature_disabled.yaml](./windows_defender_virus_scanning_feature_disabled.yaml) |
| Windows Defender Exclusions Added | medium | T1685 | [windows_defender_exclusions_added.yaml](./windows_defender_exclusions_added.yaml) |
| Windows Defender Real-Time Protection Failure/Restart | medium | T1685 | [windows_defender_real_time_protection_failure_restart.yaml](./windows_defender_real_time_protection_failure_restart.yaml) |
