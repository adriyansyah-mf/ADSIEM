# Ingestion Runtime Smoke Test

- Injected: 100 synthetic syslog events into the Redis `siem:logs` stream.
- Worker state after processing: healthy.
- Consumer pending entries: 0.
- No worker crash or processing error was observed in the post-injection log window.

This validates the Redis stream consumer path only; Elasticsearch and AI latency require a separate sustained benchmark.
