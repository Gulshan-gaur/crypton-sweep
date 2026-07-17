# Architecture

```text
CLI
├── discover       authorized TCP/TLS observation
├── inventory      CycloneDX ingestion
├── assessment     risk and migration rules
└── report         offline HTML evidence package
```

The scanner has a neutral report model. Network observations and SBOM components are normalized into assets, crypto profiles, findings, and relationships. The HTML dashboard consumes only the resulting JSON, so a future web application can reuse the same report contract without exposing scanner internals.

## Security and Privacy

The first version does not send scan results to a service. Reports are local files. Future remote integrations must make upload explicit, redact secrets, and sign report manifests.

