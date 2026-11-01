# Scenario 7: parent DS removal

This scenario removes only the `victim.test.` DS RRset with the existing TSIG
credential. The provider remains signed and the NS/glue do not change. DNSSEC
therefore treats the delegation as insecure: resolution remains `NOERROR` at
`192.0.2.10`, but the AD flag is absent. LoKey reports `DS_ALL_REMOVED` as HIGH
because no authenticated CDS deletion signal exists.

Run from the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\lab\test-ds-removal.ps1
```

Safe recovery derives the current provider DS from its authenticated DNSKEY and
restores it without touching KASP or volumes:

```powershell
powershell -ExecutionPolicy Bypass -File .\lab\reset-ds-removal.ps1
```
