---
title: "Fuzzing (experimental)"
---

<Warning>
  **Experimental**

  The fuzzer is **experimental**. The API, mutator set, and anomaly
  heuristics may change, and results should be treated as leads to
  investigate rather than confirmed findings.
</Warning>

ProtoPoke includes a replay-based fuzzer: it takes a captured session as a
baseline, mutates frame bytes each iteration, replays the session, and
flags responses that deviate from the baseline (connection resets, timeouts,
size deltas).

## Running a campaign

<Tabs>
  <Tab title="User Interface">
    On the **Fuzzer** tab (`F5`): pick a captured session, choose which
    mutators to enable, set an iteration count, optionally tick "Stop on
    crash", and click **▶ Start Campaign**. Results stream into a table
    flagged with `C` (connection reset), `T` (timeout), and `★`
    (interesting). Click a row to open the mutated bytes in the
    [Forge](/ui/forge) tab for replay.
  </Tab>
  <Tab title="Core Library">
    ```python
    from protopoke.fuzzing.mutators.raw import BitFlipMutator, KnownBadMutator

    campaign = await api.fuzz_session(
        session_id=session_id,
        mutators=[BitFlipMutator(), KnownBadMutator()],
        iterations=100,
        stop_on_crash=True,
    )

    for r in campaign.interesting_results:
        print(f"iteration {r.iteration} ({r.mutator_name}): "
              f"reset={r.connection_reset} timed_out={r.timed_out}")
    ```
  </Tab>
</Tabs>

## Built-in mutators

**Raw mutators** (no protocol definition needed): `BitFlipMutator`,
`ByteInsertMutator`, `ByteDeleteMutator`, `KnownBadMutator`,
`RadamsaMutator`, `ChainMutator`.

**Protocol-aware mutators** (require a loaded protocol definition):
`FieldBoundaryMutator`, `FieldOverflowMutator`, `NullByteMutator`,
`LengthMangleMutator`.

You can also write your own by subclassing
`protopoke.fuzzing.mutators.base.FrameMutator` and implementing
`async mutate(frame, parsed_message) -> bytes | None`, then passing an
instance in the `mutators=` list.
