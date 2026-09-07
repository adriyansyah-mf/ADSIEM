# Sigma Detection Load Baseline

- Environment: worker Docker image, local CPU
- Rule: one Sigma selection with `event.action` and `source.ip|cidr`
- Events: 10,000 synthetic events
- Matches: 10,000
- Elapsed: 0.262 seconds
- Throughput: approximately 38,186 events/second

This is a single-process matcher baseline, not an end-to-end Elasticsearch ingestion benchmark.
