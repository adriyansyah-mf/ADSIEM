# Sustained Ingestion Baseline

- Samples: 21
- Injected stream entries observed: 2,100 in this run (Redis stream total reached 5,044 including prior smoke data).
- Redis consumer pending: 0 throughout sampled tail.
- Elasticsearch documents: increased from approximately 100 to 2,205 during the run.
- Worker memory: approximately 190 MiB stable.
- Worker CPU: mostly below 1% at sample points, with brief bursts up to about 10%.
- Worker status after test: healthy.

The per-event `docker exec` generator could not sustain the requested 1,000 events/minute; a persistent Redis producer is required for the next benchmark. This run validates consumer stability and zero backlog, not target-rate capacity.
