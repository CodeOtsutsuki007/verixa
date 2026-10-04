# Audit Write Throughput

How Verixa writes audit entries under load, what batching costs, and what the
numbers mean. Issue #134. Applies to `packages/audit`.

## The problem

`packages/audit` sits downstream of every other context: registration, login,
lockout, and password reset all record an event. At any meaningful request rate
the audit write is on the same path as the traffic the system generates.

A per-event write costs two database round trips — read the chain head, insert
one entry inside a transaction — and the chain makes that sequence
irreducible: entry _n_'s hash depends on entry _n-1_'s, so it cannot be computed
in parallel and flushed afterwards. On a request path where the rest of the work
is a couple of indexed lookups, two extra round trips plus a transaction commit
is how an invisible subsystem becomes the bottleneck. Invisible, here, means
nobody notices until the log is needed and turns out to have gaps.

## What batching changes

`BatchedAuditWriter` puts a bounded in-memory queue in front of the repository
and writes pending entries as **one `createMany` per batch**.

The important design decision is what is queued: **unhashed intents**, not
finished entries. The chain is built at flush time, link by link, from a head
read immediately beforehand.

Hashing at enqueue time would look equivalent and is not. A batch built against
head _H_ and flushed after someone else appended to _H_ is a fork: N entries
claiming a predecessor that is no longer current, refused atomically by the
compare-and-set, retried, and — under sustained contention — a writer that
keeps throwing away whole batches. Building the chain as late as possible is the
only point at which a batch and a hash chain can coexist.

|                                       | Per-event                  | Batched                   |
| ------------------------------------- | -------------------------- | ------------------------- |
| Round trips for _N_ events, batch _B_ | `2N`                       | `2·⌈N/B⌉`                 |
| Transactions                          | _N_                        | `⌈N/B⌉`                   |
| Statements per insert                 | 1                          | 1                         |
| Chain build point                     | at the call                | at flush                  |
| Durability                            | before the request returns | after the next flush      |
| Memory                                | none                       | bounded by `maxQueueSize` |

## The trade being paid for

**A queued entry is not yet durable.** A process that dies with 10,000 entries
pending loses all of them, where a per-event writer loses at most the one in
flight. `flushIntervalMs` is what bounds that regression: at 250 ms the worst
case is a quarter second of audit trail rather than the whole queue.

Anyone raising `maxBatchSize` for throughput should lower the interval to match,
because otherwise the batch window silently becomes the data-loss window. The
two knobs are one decision, not two.

And `stop()` is not optional during a graceful shutdown.
`buildContainer`'s `dispose()` drains the queue before disconnecting; a
deployment that kills the process without calling it has converted a bounded
delay into permanent loss. That is the one way this design loses data in normal
operation, which is why it is stated rather than left to the reader.

## Backpressure

`maxQueueSize` is a **hard ceiling**, and the entry that gets refused is the
**newest** one — the one arriving — not the oldest queued.

Evicting oldest was the alternative considered and rejected. A caller whose
`record()` returned success has been told that entry will be written. Evicting
it later makes that promise false and turns log reliability into a function of
load, which is precisely when auditing matters most. Refusing newest keeps
`record()`'s answer honest: it reports at the moment of the call whether the
entry was accepted, and **everything accepted will be written**.

Refused entries are never silently discarded, and the queue is never an
unbounded memory grower — an unbounded queue under sustained overload is not
backpressure, it is a memory leak with a delay before the crash, and the crash
takes the whole queue's contents with it.

### Metrics

Every refusal emits an `AuditOverflowReport`: the dropped command (so an
operator can replay it), queue length and limit, and running
`overflowedTotal` / `writtenTotal` for the writer's lifetime. Overflow rate is
`overflowedTotal / writtenTotal` — the number to alert on. `BatchedAuditWriter
.stats()` exposes the counters (`pending`, `written`, `batches`, `conflicts`,
`overflowed`, `largestBatch`, `failedBatches`) for scraping.

A batch that exhausts its retries emits an `AuditBatchFailureReport` carrying
the whole batch and the error. That is a real audit gap, it is reported rather
than swallowed, and the entries are included so nothing vanishes without a
trace.

`BatchedAuditWriter.execute()` — the `AuditRecorder` port — resolves `undefined`
for both a queued entry and a refused one. It never rejects: a route awaiting an
audit write must not turn backpressure into a 500. Anything that needs to
distinguish the two is a metrics consumer and should read the reports, not infer
them from a route.

## Configuration

```bash
AUDIT_BATCHED_WRITES=1        # opt-in; unset means one write per event
AUDIT_MAX_BATCH_SIZE=100
AUDIT_FLUSH_INTERVAL_MS=250
AUDIT_MAX_QUEUE_SIZE=10000
```

The default is **per-event**. Batching changes a durability guarantee that an
operator who has not read this document will reasonably assume still holds, so
it is a deployment decision stated in configuration rather than a code default.

Malformed values fall back to the documented defaults rather than preventing
startup: these are tuning knobs for one adapter, and a typo in an interval
should not stop the API from booting.

## Load test

Not part of the default CI run. It exists to produce numbers, and numbers from a
shared runner are not comparable to anything — see
[`baseline.md`](./baseline.md) for that argument at length.

```bash
pnpm --filter @verixa/integration-tests run test:load
```

`tests/load/audit-write-throughput.load.ts` has two suites because they answer
different questions:

1. **Modelled round trips.** An instrumented repository counts statements and
   adds a fixed delay to each. Deterministic, runs with no database, and shows
   _why_ batching wins. The latency is a model, so the millisecond column is a
   model too; the statement counts and the ratio are the findings.
2. **Postgres**, when one is reachable (`TEST_DATABASE_URL`, default
   `postgres://verixa:verixa@localhost:5432/verixa_test`). Warm-up writes are
   discarded first, then 2,000 events per strategy. This is where a number worth
   writing down comes from.

Both assert chain integrity and that nothing was silently dropped. A faster
audit log whose chain does not verify is not an optimization.

### Documented volumes

200 events for the modelled comparison (4 batches of 50), 2,000 for Postgres,
batch size 50. Those are deliberately modest: the claim being tested is the
_shape_ — statements scale with `N/B` instead of `N` — not a peak-throughput
record. Anyone optimizing for a real load should measure at their own volume,
on their own hardware, and compare against their own earlier number.

### Modelled result

Recorded on the author's machine (Windows, Node 24, 200 events, batch 50,
1 ms modelled per statement). Treat the timings as indicative: Windows clamps
`setTimeout(1)` nearer 10 ms, so both columns carry the same inflated constant.

| Strategy  | Events | Statements | ms/event |
| --------- | ------ | ---------- | -------- |
| Per-event | 200    | 400        | 22.02    |
| Batched   | 200    | 8          | 0.35     |

50x fewer statements, and the throughput ratio follows directly from them. The
statement counts are exact by construction. The wall-clock ratio is not: it is
the model plus timer granularity, and it moved between runs on the same machine
(50x to 63x) depending only on what else the laptop was doing. It is reported
because the harness prints it, not because it is a result.

### Postgres result

| Strategy       | Events             | ms total | ms/event | events/s | Environment |
| -------------- | ------------------ | -------- | -------- | -------- | ----------- |
| Per-event      | _not yet recorded_ |          |          |          |             |
| Batched (B=50) | _not yet recorded_ |          |          |          |             |

**Environment:** _to be filled in when recorded — CPU, RAM, Postgres version,
containerized or not, local or remote._

Deliberately empty rather than copied from the modelled table above, for the
same reason `baseline.md` leaves its own table empty: a number that invites
comparison across machines carries more authority than it earns. Fill it in from
the machine you will measure against later.

What to expect, roughly — shape, not measurement: the gap should be large and
dominated by round trips, so a deployment on a remote database with a
half-millisecond link will see a much bigger difference than one sharing a
socket with Postgres. If batched and per-event land within 2x of each other
locally, suspect that the batch is not actually flushing as one statement before
suspecting that batching does not work.

## Rejected alternatives

**Hash entries at enqueue time and batch the inserts.** Rejected: it forks the
chain under any concurrent writer, which is the exact failure the append protocol
in [`docs/security/audit-log-integrity.md`](../security/audit-log-integrity.md)
exists to prevent.

**A dedicated append worker owning the chain.** A single writer would make the
compare-and-set unnecessary and batching trivial. Rejected: it serializes the
whole application behind one table, adds a coordination mechanism to operate and
to get wrong, and buys nothing the queue does not already provide — writes are
already batched at the repository boundary.

**Advisory locks or `SELECT … FOR UPDATE` on the head row.** Rejected: it does
not reduce round trips at all, which is the problem being solved, and it turns
throughput into a function of lock hold time. The unique index on `sequence`
already serializes correctly; the cost being removed was the number of
statements, not the contention.

**Unbounded queue, flush when full.** Rejected. See backpressure above — under
sustained overload it is a memory leak, and the crash loses everything queued,
which is the outcome the bounded queue exists to avoid.

**Evict oldest on overflow.** Rejected: it makes `record()`'s success answer
unreliable precisely under load, when the log matters most.

**`COPY` instead of `createMany`.** Genuinely faster for large batches, and
rejected on scope rather than merit: it needs raw SQL and bypasses the mapper and
the delegate interface that keeps Prisma out of everything above the adapter.
`createMany` is one statement per batch, which is where the round-trip cost
actually is. Worth revisiting with a measured case for it.

**Making batching the default.** Rejected: it silently weakens durability for
every deployment that never reads this document.

## Related

- [`docs/security/audit-log-integrity.md`](../security/audit-log-integrity.md)
- [`baseline.md`](./baseline.md)
- [`docs/guides/domain-modeling.md`](../guides/domain-modeling.md)
- [`docs/guides/configuration.md`](../guides/configuration.md)
