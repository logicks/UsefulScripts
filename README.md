# UsefulScripts

## Scripts

### [Audit-LDAPCommunications.ps1](Audit-LDAPCommunications.ps1)

Parses Windows Firewall event logs (Event ID 5156) to audit LDAP and LDAPS communications in an Active Directory environment. It identifies client IP addresses communicating with domain controllers over secure LDAP ports (636 and 3269), and highlights domain controllers that have not been observed handling any secure LDAP traffic. Subnet scoping is supported in two modes: exclude specific subnets from results, or restrict results to only clients within specified subnets. The log source can be either a pre-exported `.evtx` file (default) or a live Windows event log by name via `-LogName` (note: live log queries may be slower on busy domain controllers). Alongside optional text files listing DC IPs and CIDR subnets to filter, the script can emit a structured result object via `-PassThru` for downstream processing or export; when used, the formatted console report is suppressed.
