# Scenario 8: unsigned NS change

Scenario 8 first removes the parent DS and replaces the provider container with
an isolated unsigned view on the same IP. After the collector observes that
unsigned baseline, an authenticated registrar update changes only NS/glue to a
second unsigned authority at `172.30.0.17`, which serves `192.0.2.66`.

Both snapshots have empty DS and DNSKEY sets, so LoKey emits exactly
`NS_CHANGED` at MEDIUM risk. Recursive resolution remains `NOERROR` with no AD
flag. This differs from Scenario 6, whose attacker publishes a valid replacement
DNSSEC identity and replaces DS, and from Scenario 5's announced signed bridge.

```powershell
powershell -ExecutionPolicy Bypass -File .\lab\test-unsigned-ns-change.ps1
```

The test's `finally` path reverses NS while unsigned, restores the original
provider container and untouched `provider_state`, derives its current DS, and
restores `AD=true`. Run the reset script after interruption:

```powershell
powershell -ExecutionPolicy Bypass -File .\lab\reset-unsigned-ns-change.ps1
```
