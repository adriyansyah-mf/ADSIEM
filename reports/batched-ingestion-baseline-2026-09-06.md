# Batched Ingestion Baseline

- Producer: persistent Redis client with pipelined batches of 500.
- Events: 5,000 synthetic syslog entries.
- Producer time: 0.112 seconds.
- Consumer pending after 15 seconds: 3.
- Consumer pending after 35 seconds: 0.
- Worker remained healthy throughout the drain.

The producer path is suitable for a sustained benchmark; this run validates batching and queue drain rather than a 15-minute steady-state rate.
