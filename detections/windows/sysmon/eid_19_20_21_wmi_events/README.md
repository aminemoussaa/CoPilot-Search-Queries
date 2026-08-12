# eid 19 20 21 wmi events

Sysmon Event IDs 19/20/21 — WMI event filter, consumer and binding.

**4 rules** — high 3, medium 1

> Generated index. Severity and MITRE columns are read from each rule file.

| Rule | Severity | MITRE ATT&CK | File |
| --- | --- | --- | --- |
| Suspicious Encoded Scripts in a WMI Consumer | high | T1047, T1546.003 | [suspicious_encoded_scripts_in_a_wmi_consumer.yaml](./suspicious_encoded_scripts_in_a_wmi_consumer.yaml) |
| Suspicious Scripting in a WMI Consumer | high | T1059.005 | [suspicious_scripting_in_a_wmi_consumer.yaml](./suspicious_scripting_in_a_wmi_consumer.yaml) |
| Windows WMI Permanent Event Subscription | high | T1546.003 | [wmi_permanent_event_subscription_sysmon.yaml](./wmi_permanent_event_subscription_sysmon.yaml) |
| WMI Event Subscription | medium | T1546.003 | [wmi_event_subscription.yaml](./wmi_event_subscription.yaml) |
