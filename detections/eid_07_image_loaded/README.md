# eid 07 image loaded

Sysmon Event ID 7 — image / DLL loaded.

**113 rules** — critical 5, high 55, medium 52, low 1

> Generated index. Severity and MITRE columns are read from each rule file.

| Rule | Severity | MITRE ATT&CK | File |
| --- | --- | --- | --- |
| FoggyWeb Backdoor DLL Loading | critical | T1587 | [foggyweb_backdoor_dll_loading.yaml](./foggyweb_backdoor_dll_loading.yaml) |
| Malicious DLL Load By Compromised 3CXDesktopApp | critical | — | [malicious_dll_load_by_compromised_3cxdesktopapp.yaml](./malicious_dll_load_by_compromised_3cxdesktopapp.yaml) |
| Potential DCOM InternetExplorer.Application DLL Hijack - Image Load | critical | T1021.002, T1021.003 | [potential_dcom_internetexplorer_application_dll_hijack_image_load.yaml](./potential_dcom_internetexplorer_application_dll_hijack_image_load.yaml) |
| Windows Executable in Loaded Modules | critical | T1129 | [windows_executable_in_loaded_modules.yaml](./windows_executable_in_loaded_modules.yaml) |
| Windows Known GraphicalProton Loaded Modules | critical | T1574.001 | [windows_known_graphicalproton_loaded_modules.yaml](./windows_known_graphicalproton_loaded_modules.yaml) |
| Abusable DLL Potential Sideloading From Suspicious Location | high | T1059 | [abusable_dll_potential_sideloading_from_suspicious_location.yaml](./abusable_dll_potential_sideloading_from_suspicious_location.yaml) |
| APT PRIVATELOG Image Load Pattern | high | T1055 | [apt_privatelog_image_load_pattern.yaml](./apt_privatelog_image_load_pattern.yaml) |
| Aruba Network Service Potential DLL Sideloading | high | T1574.001 | [aruba_network_service_potential_dll_sideloading.yaml](./aruba_network_service_potential_dll_sideloading.yaml) |
| BaaUpdate.exe Suspicious DLL Load | high | T1218, T1021.003 | [baaupdate_exe_suspicious_dll_load.yaml](./baaupdate_exe_suspicious_dll_load.yaml) |
| Diagnostic Library Sdiageng.DLL Loaded By Msdt.EXE | high | T1202 | [diagnostic_library_sdiageng_dll_loaded_by_msdt_exe.yaml](./diagnostic_library_sdiageng_dll_loaded_by_msdt_exe.yaml) |
| Diamond Sleet APT DLL Sideloading Indicators | high | T1574.001 | [diamond_sleet_apt_dll_sideloading_indicators.yaml](./diamond_sleet_apt_dll_sideloading_indicators.yaml) |
| DLL Loaded From Suspicious Location Via Cmspt.EXE | high | T1218.003 | [dll_loaded_from_suspicious_location_via_cmspt_exe.yaml](./dll_loaded_from_suspicious_location_via_cmspt_exe.yaml) |
| DLL Sideloading Of ShellChromeAPI.DLL | high | T1574.001 | [dll_sideloading_of_shellchromeapi_dll.yaml](./dll_sideloading_of_shellchromeapi_dll.yaml) |
| DotNet CLR DLL Loaded By Scripting Applications | high | T1055 | [dotnet_clr_dll_loaded_by_scripting_applications.yaml](./dotnet_clr_dll_loaded_by_scripting_applications.yaml) |
| Fax Service DLL Search Order Hijack | high | T1574.001 | [fax_service_dll_search_order_hijack.yaml](./fax_service_dll_search_order_hijack.yaml) |
| GAC DLL Loaded Via Office Applications | high | T1204.002 | [gac_dll_loaded_via_office_applications.yaml](./gac_dll_loaded_via_office_applications.yaml) |
| HackTool - SharpEvtMute DLL Load | high | T1685.001 | [hacktool_sharpevtmute_dll_load.yaml](./hacktool_sharpevtmute_dll_load.yaml) |
| HackTool - SILENTTRINITY Stager DLL Load | high | T1071 | [hacktool_silenttrinity_stager_dll_load.yaml](./hacktool_silenttrinity_stager_dll_load.yaml) |
| Kapeka Backdoor Loaded Via Rundll32.EXE | high | T1204.002, T1218.011 | [kapeka_backdoor_loaded_via_rundll32_exe.yaml](./kapeka_backdoor_loaded_via_rundll32_exe.yaml) |
| Katz Stealer DLL Loaded | high | T1129 | [katz_stealer_dll_loaded.yaml](./katz_stealer_dll_loaded.yaml) |
| Lazarus APT DLL Sideloading Activity | high | T1574.001 | [lazarus_apt_dll_sideloading_activity.yaml](./lazarus_apt_dll_sideloading_activity.yaml) |
| Load Of RstrtMgr.DLL By A Suspicious Process | high | T1486, T1685 | [load_of_rstrtmgr_dll_by_a_suspicious_process.yaml](./load_of_rstrtmgr_dll_by_a_suspicious_process.yaml) |
| Microsoft Office DLL Sideload | high | T1574.001 | [microsoft_office_dll_sideload.yaml](./microsoft_office_dll_sideload.yaml) |
| PCRE.NET Package Image Load | high | T1059 | [pcre_net_package_image_load.yaml](./pcre_net_package_image_load.yaml) |
| Pingback Backdoor DLL Loading Activity | high | T1574.001 | [pingback_backdoor_dll_loading_activity.yaml](./pingback_backdoor_dll_loading_activity.yaml) |
| Potential appverifUI.DLL Sideloading | high | T1574.001 | [potential_appverifui_dll_sideloading.yaml](./potential_appverifui_dll_sideloading.yaml) |
| Potential COLDSTEEL Persistence Service DLL Load | high | — | [potential_coldsteel_persistence_service_dll_load.yaml](./potential_coldsteel_persistence_service_dll_load.yaml) |
| Potential DLL Sideloading Of KeyScramblerIE.DLL Via KeyScrambler.EXE | high | T1574.001 | [potential_dll_sideloading_of_keyscramblerie_dll_via_keyscrambler_exe.yaml](./potential_dll_sideloading_of_keyscramblerie_dll_via_keyscrambler_exe.yaml) |
| Potential DLL Sideloading Of Non-Existent DLLs From System Folders | high | T1574.001 | [potential_dll_sideloading_of_non_existent_dlls_from_system_folders.yaml](./potential_dll_sideloading_of_non_existent_dlls_from_system_folders.yaml) |
| Potential DLL Sideloading Via comctl32.dll | high | T1574.001 | [potential_dll_sideloading_via_comctl32_dll.yaml](./potential_dll_sideloading_via_comctl32_dll.yaml) |
| Potential DLL Sideloading Via VMware Xfer | high | T1574.001 | [potential_dll_sideloading_via_vmware_xfer.yaml](./potential_dll_sideloading_via_vmware_xfer.yaml) |
| Potential EACore.DLL Sideloading | high | T1574.001 | [potential_eacore_dll_sideloading.yaml](./potential_eacore_dll_sideloading.yaml) |
| Potential Edputil.DLL Sideloading | high | T1574.001 | [potential_edputil_dll_sideloading.yaml](./potential_edputil_dll_sideloading.yaml) |
| Potential Exploitation of RCE Vulnerability CVE-2025-33053 - Image Load | high | T1218, T1105 | [potential_exploitation_of_rce_vulnerability_cve_2025_33053_image_load.yaml](./potential_exploitation_of_rce_vulnerability_cve_2025_33053_image_load.yaml) |
| Potential Iviewers.DLL Sideloading | high | T1574.001 | [potential_iviewers_dll_sideloading.yaml](./potential_iviewers_dll_sideloading.yaml) |
| Potential JLI.dll Side-Loading | high | T1574.001 | [potential_jli_dll_side_loading.yaml](./potential_jli_dll_side_loading.yaml) |
| Potential Mpclient.DLL Sideloading | high | T1574.001 | [potential_mpclient_dll_sideloading.yaml](./potential_mpclient_dll_sideloading.yaml) |
| Potential Raspberry Robin Aclui Dll SideLoading | high | T1574.001 | [potential_raspberry_robin_aclui_dll_sideloading.yaml](./potential_raspberry_robin_aclui_dll_sideloading.yaml) |
| Potential Rcdll.DLL Sideloading | high | T1574.001 | [potential_rcdll_dll_sideloading.yaml](./potential_rcdll_dll_sideloading.yaml) |
| Potential RjvPlatform.DLL Sideloading From Non-Default Location | high | T1574.001 | [potential_rjvplatform_dll_sideloading_from_non_default_location.yaml](./potential_rjvplatform_dll_sideloading_from_non_default_location.yaml) |
| Potential SmadHook.DLL Sideloading | high | T1574.001 | [potential_smadhook_dll_sideloading.yaml](./potential_smadhook_dll_sideloading.yaml) |
| Potential Vcruntime140 DLL Sideloading | high | T1574.001 | [potential_vcruntime140_dll_sideloading.yaml](./potential_vcruntime140_dll_sideloading.yaml) |
| Potential Waveedit.DLL Sideloading | high | T1574.001 | [potential_waveedit_dll_sideloading.yaml](./potential_waveedit_dll_sideloading.yaml) |
| Suspicious Loading of Dbgcore/Dbghelp DLLs from Uncommon Location | high | T1003, T1685 | [suspicious_loading_of_dbgcore_dbghelp_dlls_from_uncommon_location.yaml](./suspicious_loading_of_dbgcore_dbghelp_dlls_from_uncommon_location.yaml) |
| Suspicious Renamed Comsvcs DLL Loaded By Rundll32 | high | T1003.001 | [suspicious_renamed_comsvcs_dll_loaded_by_rundll32.yaml](./suspicious_renamed_comsvcs_dll_loaded_by_rundll32.yaml) |
| Suspicious Unsigned Dbghelp/Dbgcore DLL Loaded | high | T1003.001 | [suspicious_unsigned_dbghelp_dbgcore_dll_loaded.yaml](./suspicious_unsigned_dbghelp_dbgcore_dll_loaded.yaml) |
| Suspicious Unsigned Thor Scanner Execution | high | T1574.001 | [suspicious_unsigned_thor_scanner_execution.yaml](./suspicious_unsigned_thor_scanner_execution.yaml) |
| Suspicious Volume Shadow Copy VSS_PS.dll Load | high | T1490 | [suspicious_volume_shadow_copy_vss_ps_dll_load.yaml](./suspicious_volume_shadow_copy_vss_ps_dll_load.yaml) |
| Suspicious Volume Shadow Copy Vssapi.dll Load | high | T1490 | [suspicious_volume_shadow_copy_vssapi_dll_load.yaml](./suspicious_volume_shadow_copy_vssapi_dll_load.yaml) |
| System Control Panel Item Loaded From Uncommon Location | high | T1574.001 | [system_control_panel_item_loaded_from_uncommon_location.yaml](./system_control_panel_item_loaded_from_uncommon_location.yaml) |
| Time Travel Debugging Utility Usage - Image | high | T1218, T1003.001 | [time_travel_debugging_utility_usage_image.yaml](./time_travel_debugging_utility_usage_image.yaml) |
| Trusted Path Bypass via Windows Directory Spoofing | high | T1574.007, T1548.002 | [trusted_path_bypass_via_windows_directory_spoofing.yaml](./trusted_path_bypass_via_windows_directory_spoofing.yaml) |
| UAC Bypass Using Iscsicpl - ImageLoad | high | T1548.002 | [uac_bypass_using_iscsicpl_imageload.yaml](./uac_bypass_using_iscsicpl_imageload.yaml) |
| UAC Bypass With Fake DLL | high | T1548.002, T1574.001 | [uac_bypass_with_fake_dll.yaml](./uac_bypass_with_fake_dll.yaml) |
| Unsigned Mfdetours.DLL Sideloading | high | T1574.001 | [unsigned_mfdetours_dll_sideloading.yaml](./unsigned_mfdetours_dll_sideloading.yaml) |
| VBA DLL Loaded Via Office Application | high | T1204.002 | [vba_dll_loaded_via_office_application.yaml](./vba_dll_loaded_via_office_application.yaml) |
| VMMap Unsigned Dbghelp.DLL Potential Sideloading | high | T1574.001 | [vmmap_unsigned_dbghelp_dll_potential_sideloading.yaml](./vmmap_unsigned_dbghelp_dll_potential_sideloading.yaml) |
| Windows Credentials Access Via Vaultcli Module | high | T1555.004 | [windows_credentials_access_via_vaultcli_module.yaml](./windows_credentials_access_via_vaultcli_module.yaml) |
| WMI Persistence - Command Line Event Consumer | high | T1546.003 | [wmi_persistence_command_line_event_consumer.yaml](./wmi_persistence_command_line_event_consumer.yaml) |
| Wmiprvse Wbemcomn DLL Hijack | high | T1047, T1021.002 | [wmiprvse_wbemcomn_dll_hijack.yaml](./wmiprvse_wbemcomn_dll_hijack.yaml) |
| Amsi.DLL Loaded Via LOLBIN Process | medium | — | [amsi_dll_loaded_via_lolbin_process.yaml](./amsi_dll_loaded_via_lolbin_process.yaml) |
| Clfs.SYS Loaded By Process Located In a Potential Suspicious Location | medium | T1059 | [clfs_sys_loaded_by_process_located_in_a_potential_suspicious_location.yaml](./clfs_sys_loaded_by_process_located_in_a_potential_suspicious_location.yaml) |
| CLR DLL Loaded Via Office Applications | medium | T1204.002 | [clr_dll_loaded_via_office_applications.yaml](./clr_dll_loaded_via_office_applications.yaml) |
| CredUI.DLL Loaded By Uncommon Process | medium | T1056.002 | [credui_dll_loaded_by_uncommon_process.yaml](./credui_dll_loaded_by_uncommon_process.yaml) |
| DLL Load By System Process From Suspicious Locations | medium | T1070 | [dll_load_by_system_process_from_suspicious_locations.yaml](./dll_load_by_system_process_from_suspicious_locations.yaml) |
| DLL Names Used By SVR For GraphicalProton Backdoor | medium | T1574.001 | [dll_names_used_by_svr_for_graphicalproton_backdoor.yaml](./dll_names_used_by_svr_for_graphicalproton_backdoor.yaml) |
| DotNET Assembly DLL Loaded Via Office Application | medium | T1204.002 | [dotnet_assembly_dll_loaded_via_office_application.yaml](./dotnet_assembly_dll_loaded_via_office_application.yaml) |
| Microsoft Excel Add-In Loaded From Uncommon Location | medium | T1204.002 | [microsoft_excel_add_in_loaded_from_uncommon_location.yaml](./microsoft_excel_add_in_loaded_from_uncommon_location.yaml) |
| Microsoft VBA For Outlook Addin Loaded Via Outlook | medium | T1204.002 | [microsoft_vba_for_outlook_addin_loaded_via_outlook.yaml](./microsoft_vba_for_outlook_addin_loaded_via_outlook.yaml) |
| MMC Loading Script Engines DLLs | medium | T1059.005, T1218.014 | [mmc_loading_script_engines_dlls.yaml](./mmc_loading_script_engines_dlls.yaml) |
| Potential Antivirus Software DLL Sideloading | medium | T1574.001 | [potential_antivirus_software_dll_sideloading.yaml](./potential_antivirus_software_dll_sideloading.yaml) |
| Potential AVKkid.DLL Sideloading | medium | T1574.001 | [potential_avkkid_dll_sideloading.yaml](./potential_avkkid_dll_sideloading.yaml) |
| Potential CCleanerDU.DLL Sideloading | medium | T1574.001 | [potential_ccleanerdu_dll_sideloading.yaml](./potential_ccleanerdu_dll_sideloading.yaml) |
| Potential CCleanerReactivator.DLL Sideloading | medium | T1574.001 | [potential_ccleanerreactivator_dll_sideloading.yaml](./potential_ccleanerreactivator_dll_sideloading.yaml) |
| Potential Chrome Frame Helper DLL Sideloading | medium | T1574.001 | [potential_chrome_frame_helper_dll_sideloading.yaml](./potential_chrome_frame_helper_dll_sideloading.yaml) |
| Potential CVE-2024-35250 Exploitation Activity | medium | T1068 | [potential_cve_2024_35250_exploitation_activity.yaml](./potential_cve_2024_35250_exploitation_activity.yaml) |
| Potential DLL Sideloading Of DBGCORE.DLL | medium | T1574.001 | [potential_dll_sideloading_of_dbgcore_dll.yaml](./potential_dll_sideloading_of_dbgcore_dll.yaml) |
| Potential DLL Sideloading Of DBGHELP.DLL | medium | T1574.001 | [potential_dll_sideloading_of_dbghelp_dll.yaml](./potential_dll_sideloading_of_dbghelp_dll.yaml) |
| Potential DLL Sideloading Of DbgModel.DLL | medium | T1574.001 | [potential_dll_sideloading_of_dbgmodel_dll.yaml](./potential_dll_sideloading_of_dbgmodel_dll.yaml) |
| Potential DLL Sideloading Of Libcurl.DLL Via GUP.EXE | medium | T1574.001 | [potential_dll_sideloading_of_libcurl_dll_via_gup_exe.yaml](./potential_dll_sideloading_of_libcurl_dll_via_gup_exe.yaml) |
| Potential DLL Sideloading Of MpSvc.DLL | medium | T1574.001 | [potential_dll_sideloading_of_mpsvc_dll.yaml](./potential_dll_sideloading_of_mpsvc_dll.yaml) |
| Potential DLL Sideloading Of MsCorSvc.DLL | medium | T1574.001 | [potential_dll_sideloading_of_mscorsvc_dll.yaml](./potential_dll_sideloading_of_mscorsvc_dll.yaml) |
| Potential DLL Sideloading Using Coregen.exe | medium | T1218, T1055 | [potential_dll_sideloading_using_coregen_exe.yaml](./potential_dll_sideloading_using_coregen_exe.yaml) |
| Potential DLL Sideloading Via ClassicExplorer32.dll | medium | T1574.001 | [potential_dll_sideloading_via_classicexplorer32_dll.yaml](./potential_dll_sideloading_via_classicexplorer32_dll.yaml) |
| Potential DLL Sideloading Via JsSchHlp | medium | T1574.001 | [potential_dll_sideloading_via_jsschhlp.yaml](./potential_dll_sideloading_via_jsschhlp.yaml) |
| Potential Goopdate.DLL Sideloading | medium | T1574.001 | [potential_goopdate_dll_sideloading.yaml](./potential_goopdate_dll_sideloading.yaml) |
| Potential Libvlc.DLL Sideloading | medium | T1574.001 | [potential_libvlc_dll_sideloading.yaml](./potential_libvlc_dll_sideloading.yaml) |
| Potential Mfdetours.DLL Sideloading | medium | T1574.001 | [potential_mfdetours_dll_sideloading.yaml](./potential_mfdetours_dll_sideloading.yaml) |
| Potential Python DLL SideLoading | medium | T1574.001 | [potential_python_dll_sideloading.yaml](./potential_python_dll_sideloading.yaml) |
| Potential RjvPlatform.DLL Sideloading From Default Location | medium | T1574.001 | [potential_rjvplatform_dll_sideloading_from_default_location.yaml](./potential_rjvplatform_dll_sideloading_from_default_location.yaml) |
| Potential RoboForm.DLL Sideloading | medium | T1574.001 | [potential_roboform_dll_sideloading.yaml](./potential_roboform_dll_sideloading.yaml) |
| Potential ShellDispatch.DLL Sideloading | medium | T1574.001 | [potential_shelldispatch_dll_sideloading.yaml](./potential_shelldispatch_dll_sideloading.yaml) |
| Potential SolidPDFCreator.DLL Sideloading | medium | T1574.001 | [potential_solidpdfcreator_dll_sideloading.yaml](./potential_solidpdfcreator_dll_sideloading.yaml) |
| Potential Vivaldi_elf.DLL Sideloading | medium | T1574.001 | [potential_vivaldi_elf_dll_sideloading.yaml](./potential_vivaldi_elf_dll_sideloading.yaml) |
| Potential Wazuh Security Platform DLL Sideloading | medium | T1574.001 | [potential_wazuh_security_platform_dll_sideloading.yaml](./potential_wazuh_security_platform_dll_sideloading.yaml) |
| Potential WWlib.DLL Sideloading | medium | T1574.001 | [potential_wwlib_dll_sideloading.yaml](./potential_wwlib_dll_sideloading.yaml) |
| Potentially Suspicious Volume Shadow Copy Vsstrace.dll Load | medium | T1490 | [potentially_suspicious_volume_shadow_copy_vsstrace_dll_load.yaml](./potentially_suspicious_volume_shadow_copy_vsstrace_dll_load.yaml) |
| PowerShell Core DLL Loaded By Non PowerShell Process | medium | T1059.001 | [powershell_core_dll_loaded_by_non_powershell_process.yaml](./powershell_core_dll_loaded_by_non_powershell_process.yaml) |
| PowerShell Core DLL Loaded Via Office Application | medium | — | [powershell_core_dll_loaded_via_office_application.yaml](./powershell_core_dll_loaded_via_office_application.yaml) |
| Remote DLL Load Via Rundll32.EXE | medium | T1204.002 | [remote_dll_load_via_rundll32_exe.yaml](./remote_dll_load_via_rundll32_exe.yaml) |
| Suspicious WSMAN Provider Image Loads | medium | T1059.001, T1021.003 | [suspicious_wsman_provider_image_loads.yaml](./suspicious_wsman_provider_image_loads.yaml) |
| Third Party Software DLL Sideloading | medium | T1574.001 | [third_party_software_dll_sideloading.yaml](./third_party_software_dll_sideloading.yaml) |
| Unsigned .node File Loaded | medium | T1129, T1574.001, T1036.005 | [unsigned_node_file_loaded.yaml](./unsigned_node_file_loaded.yaml) |
| Unsigned DLL Loaded by Windows Utility | medium | T1218.011, T1218.010 | [unsigned_dll_loaded_by_windows_utility.yaml](./unsigned_dll_loaded_by_windows_utility.yaml) |
| Unsigned Image Loaded Into LSASS Process | medium | T1003.001 | [unsigned_image_loaded_into_lsass_process.yaml](./unsigned_image_loaded_into_lsass_process.yaml) |
| Unsigned Module Loaded by ClickOnce Application | medium | T1574.001 | [unsigned_module_loaded_by_clickonce_application.yaml](./unsigned_module_loaded_by_clickonce_application.yaml) |
| VMGuestLib DLL Sideload | medium | T1574.001 | [vmguestlib_dll_sideload.yaml](./vmguestlib_dll_sideload.yaml) |
| VMMap Signed Dbghelp.DLL Potential Sideloading | medium | T1574.001 | [vmmap_signed_dbghelp_dll_potential_sideloading.yaml](./vmmap_signed_dbghelp_dll_potential_sideloading.yaml) |
| Windows DLL Module Loaded in Temp Dir | medium | T1105 | [windows_dll_module_loaded_in_temp_dir.yaml](./windows_dll_module_loaded_in_temp_dir.yaml) |
| Windows NetSupport RMM DLL Loaded By Uncommon Process | medium | T1036 | [windows_netsupport_rmm_dll_loaded_by_uncommon_process.yaml](./windows_netsupport_rmm_dll_loaded_by_uncommon_process.yaml) |
| WMI ActiveScriptEventConsumers Activity Via Scrcons.EXE DLL Load | medium | T1546.003 | [wmi_activescripteventconsumers_activity_via_scrcons_exe_dll_load.yaml](./wmi_activescripteventconsumers_activity_via_scrcons_exe_dll_load.yaml) |
| WMIC Loading Scripting Libraries | medium | T1220 | [wmic_loading_scripting_libraries.yaml](./wmic_loading_scripting_libraries.yaml) |
| Windows DLL Search Order Hijacking Hunt with Sysmon | low | T1574.001 | [windows_dll_search_order_hijacking_hunt_with_sysmon.yaml](./windows_dll_search_order_hijacking_hunt_with_sysmon.yaml) |
