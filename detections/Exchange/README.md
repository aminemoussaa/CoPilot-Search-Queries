# exchange

Office 365 Management Activity API, `Exchange` workload — mailbox rules, forwarding, mass deletion.

**4 rules** — high 3, medium 1

> Generated index. Severity and MITRE columns are read from each rule file.

| Rule | Severity | MITRE ATT&CK | File |
| --- | --- | --- | --- |
| M365 Email Forwarding Created | high | T1114.003 | [m365_email_forwarding_created.yaml](./m365_email_forwarding_created.yaml) |
| M365 Inbox Rule Created | high | T1114.003, T1564.008 | [m365_inbox_rule_created.yaml](./m365_inbox_rule_created.yaml) |
| M365 Mass Email Deletion - Evidence Wipe | high | T1070.008, T1114 | [m365_mass_email_deletion_evidence_wipe.yaml](./m365_mass_email_deletion_evidence_wipe.yaml) |
| New Federated Domain Added - Exchange | medium | T1136.003 | [new_federated_domain_added_exchange.yaml](./new_federated_domain_added_exchange.yaml) |
