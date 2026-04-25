# Monad Audit — Findings Summary & Knowledge Notes

**Report:** <https://code4rena.com/reports/2025-09-monad>  
**Audit Period:** September 15 – October 12, 2025  
**Total Findings:** 4 High, 7 Medium, 2 Low (published)
---

## High Risk Findings

---

### H-01 — Block policy discounts gas price by incorrectly applying EIP-1559 to legacy transactions

**Link:** <https://code4rena.com/reports/2025-09-monad#h-01-block-policy-discounts-gas-price-by-incorrectly-applying-eip-1559-to-legacy-transactions>
The consensus layer's `compute_txn_max_gas_cost` function applies the EIP-1559 gas cap formula (`min(max_fee, base_fee + priority_fee)`) to all transaction types, including legacy transactions. For legacy transactions, `max_priority_fee_per_gas` is absent and defaults to 0, causing the formula to return `base_fee` as the gas bid instead of the actual `gas_price`. This underestimates the true cost, allowing underfunded transactions into blocks that the execution layer then rejects as invalid — enabling DoS and a free gas bypass.
**Knowledge needed to catch this bug:**

- Understand the field differences between legacy and EIP-1559 transactions: legacy has a single `gas_price`, while EIP-1559 splits this into `max_fee_per_gas` and `max_priority_fee_per_gas`. Applying the EIP-1559 cap formula to legacy fields produces a completely different (and wrong) result.
- Know how compatibility shims work in transaction abstraction libraries (e.g., alloy's `TxEnvelope`): when `max_priority_fee_per_gas()` is called on a legacy transaction, it returns `None`, and a naïve `unwrap_or(0)` silently introduces the bug.
- Recognize that in architectures where consensus leads execution, any divergence between how the two layers calculate costs creates an exploitable gap — the consensus layer acts as the gatekeeper, so its logic must exactly mirror the execution layer's logic.

---

### H-02 — Attacker can send malicious EIP-7702 transactions that cause rounds to time out and halt the chain

**Link:** <https://code4rena.com/reports/2025-09-monad#h-02-attacker-can-send-malicious-eip-7702-transactions-that-cause-rounds-to-time-out-and-halt-the-chain>
The mempool and block validator apply the same two EIP-7702 authorization checks — `chain_id` validity and `SYSTEM_SENDER_ETH_ADDRESS` — but in opposite order. An attacker can craft a transaction with `authority = SYSTEM_SENDER_ETH_ADDRESS` and an invalid `chain_id`. The mempool rejects the authorization on `chain_id` first (never reaching the system sender check), so the transaction is admitted. The block validator checks `SYSTEM_SENDER_ETH_ADDRESS` first, immediately invalidating the whole block. Since the transaction is never executed, it costs nothing and can be resubmitted indefinitely, halting the chain.
**Knowledge needed to catch this bug:**

- When multiple validation components process the same transaction, they must apply checks in a consistent order. Inconsistent ordering creates a class of inputs that pass one gate but fail another — a logic gap attackers can deliberately target.
- Understand that pre-execution block rejection means the attacker pays no fees — the economic deterrent of gas only applies to executed transactions. Any attack path that avoids execution is effectively free and can be repeated indefinitely.
- Know the Monad-specific concept of `SYSTEM_SENDER_ETH_ADDRESS` and why it must be guarded at the earliest possible validation point (mempool admission), not just at the block validation stage.

---

### H-03 — Incorrect affordability checks admit invalid transactions allowing txpool and block building DoS

**Link:** <https://code4rena.com/reports/2025-09-monad#h-03-incorrect-affordability-checks-admits-invalid-transactions-allowing-txpool-and-block-building-dos>
At insert time, the txpool checks affordability using only `base_fee × gas_limit`, ignoring the priority fee. At proposal time, the full EIP-1559 gas bid (`base_fee + priority_fee`) is used. An attacker can submit high-tip transactions from accounts with just enough balance to pass the insert-time check but not the proposal-time check. These transactions flood the pool, are repeatedly selected for proposals, fail, and are returned to the pool rather than evicted — causing block building starvation and preventing honest transactions from being admitted.
**Knowledge needed to catch this bug:**

- Identify when the same value (effective gas cost) is computed differently at different pipeline stages. Any gap between an admission check and an enforcement check is a potential stuffing vector.
- Understand txpool eviction and promotion policies: if invalid transactions are returned to the pool rather than evicted, the pool can become permanently polluted. Knowing the lifecycle of a rejected transaction is essential.
- Recognize that DoS via pool stuffing can be extremely cheap — the attacker only needs enough balance to pass a weakened gate, and since transactions are never included, no funds are actually spent.

---

### H-04 — EIP-7702 order-dependent delegated-status mismatch enables persistent free chain DoS

**Link:** <https://code4rena.com/reports/2025-09-monad#h-04-eip-7702-order-dependent-delegated-status-mismatch-enables-persistent-free-chain-dos>
The txpool and block policy apply EIP-7702 delegation status at different times and with different ordering semantics. The txpool marks an authority as "delegated" only after including the EIP-7702 transaction during proposal assembly (order-sensitive). Block policy pre-marks all authorities in the entire block as delegated before any per-transaction checks (order-insensitive). An attacker submits a high-tip EIP-1559 tx and a lower-tip EIP-7702 tx for the same authority. The txpool admits the EIP-1559 tx under "emptying" rules (not delegated yet), but block policy sees the authority as delegated globally and re-evaluates it under stricter "reserve" rules, causing the block to be rejected pre-execution — for free, repeatedly.
**Knowledge needed to catch this bug:**

- Understand the EIP-7702 delegation model and how "delegated" vs "non-delegated" account status changes which balance rules apply (emptying path vs reserve path). The classification of the same transaction can differ based on context.
- Recognize that "order-sensitive" vs "order-insensitive" state derivation between two components is a semantic mismatch that can be weaponized — when the txpool and block policy derive the same state differently, there will always be edge-case inputs that are classified differently by each.
- Know that pre-execution block rejection = zero cost to the attacker. Any bug that causes consensus rejection before execution is a free, repeatable DoS primitive.

---

## Medium Risk Findings

---

### M-01 — Lack of authorization in RaptorCast Secondary protocol group messages allows arbitrary node impersonation leading to DoS

**Link:** <https://code4rena.com/reports/2025-09-monad#m-01-lack-of-authorization-in-raptorcast-secondary-protocol-group-messages-allows-arbitrary-node-impersonation-leading-to-dos>
RaptorCast Secondary messages are cryptographically signed, but the application layer never verifies that identity fields within the message payload (e.g., `validator_id`, `node_id`) match the recovered public key from the signature. This allows anyone to impersonate any validator or full node in the group formation protocol, enabling slot exhaustion DoS, fake peer injection, and redirection of full nodes to attacker-controlled infrastructure.
**Knowledge needed to catch this bug:**

- Understand the difference between "the signature is valid" and "the claimed identity matches the signer." Verifying a signature proves the message was not tampered with, but does not prove the sender is who the payload claims they are.
- Know the group formation protocol flow well enough to identify what an attacker gains by impersonating each role — a signature check without an identity binding check is an incomplete security control.
- Recognize that unauthenticated network protocols are high-value targets: if any open port can be used to inject crafted messages at zero cost, the attack surface is extremely broad.

---

### M-02 — Bounded channel panic in TokioTaskUpdater causes node crash leading to realistic chain halt

**Link:** <https://code4rena.com/reports/2025-09-monad#m-02-bounded-channel-panic-in-tokiotaskupdater-causes-node-crash-leading-to-realistic-chain-halt>
The `TokioTaskUpdater` executor uses a bounded channel of 1024 slots for command batches and calls `.expect()` on `try_send()`. If more than 1024 batches are queued (achievable by an unauthenticated attacker sending `ForwardedTx` messages in bulk), the executor panics and crashes the node. Because any discoverable node is reachable and the channel is small, an attacker can bring down the entire validator set and halt the chain.
**Knowledge needed to catch this bug:**

- Treat every `.expect()` / `.unwrap()` on a fallible operation in networked, concurrent code as a potential DoS vector — panics in async executors crash the entire process.
- Know how bounded channels work and that `try_send` fails (rather than blocks) when full. Any external actor that can control message rate can deliberately overflow a bounded channel if there is no backpressure.
- Understand the threat model for unauthenticated endpoints: if a port must be open for peer communication, any logic reachable through that port with no rate limiting or authentication is a viable DoS surface.

---

### M-03 — Remote process crash (OOM) via post-serialization size check and large batch aggregation in JSON-RPC

**Link:** <https://code4rena.com/reports/2025-09-monad#m-03-remote-process-crash-oom-via-post-serialization-size-check-and-large-batch-aggregation-in-json-rpc>
The JSON-RPC server fully materializes and serializes entire batch responses in memory before checking against the size cap. With default settings allowing up to 5,000 requests per batch and expensive endpoints like `eth_getLogs`, an attacker can force the server to allocate gigabytes of memory before the size check fires, crashing the process via OOM. The check is applied too late to prevent the allocation.
**Knowledge needed to catch this bug:**

- Know the "check before allocate" principle: size or rate limits must be enforced *before* the expensive work is done, not after. A post-serialization size check is a common antipattern that provides no protection against memory exhaustion.
- Understand which RPC endpoints have large or unbounded response sizes (e.g., `eth_getLogs`, `eth_feeHistory`) and that these need per-endpoint concurrency/size guards, not just a global cap.
- Recognize that default configuration values matter for security — large `batch_request_limit` and `max_response_size` defaults can make a theoretical issue easily exploitable in practice.

---

### M-04 — Incorrect write position in block device trim operation

**Link:** <https://code4rena.com/reports/2025-09-monad#m-04-incorrect-write-position-in-block-device-trim-operation>
In `chunk::try_trim_contents()`, when a trim boundary falls within a disk page, the code advances a range pointer to skip the partial page during the trim operation, but then uses the already-advanced pointer as the write offset for saving the preserved partial page. This writes data to the wrong disk location, corrupting the subsequent page's data.
**Knowledge needed to catch this bug:**

- When a variable is mutated for one purpose (advancing a range for a trim), always check whether it is reused downstream for a different purpose (as a write offset). Mutating shared state for one step and then reusing it in another is a classic off-by-one/wrong-offset class of bug.
- Understand the expected semantics of partial-page preservation during trim: the preserved fragment must be written back to its *original* location, not the advanced one.
- Low-level storage code benefits from clearly separating mutable loop/range variables from address variables used for I/O — or using a saved copy of the original before mutation.

---

### M-05 — Typed receipt encoding does not conform to standard Ethereum RPC format

**Link:** <https://code4rena.com/reports/2025-09-monad#m-05-typed-receipt-encoding-does-not-conform-to-standard-ethereum-rpc-format>
The `debug_getRawReceipts` RPC method uses plain RLP encoding (`r.encode()`) instead of EIP-2718 encoding (`r.encode_2718()`) for typed transaction receipts. This omits the required transaction type prefix byte, producing malformed receipts that violate the EIP-2718 spec and break any tool or client that expects standards-compliant receipt encoding.
**Knowledge needed to catch this bug:**

- Know the EIP-2718 typed transaction envelope standard: typed receipts must be prefixed with the transaction type byte. Plain RLP encoding is only correct for legacy (type 0) receipts.
- When reviewing encoding logic, always check whether the correct encoding method is used for each type in a type-dispatched system — especially when an abstraction library provides both a legacy and a typed encoding method (e.g., `encode` vs `encode_2718`).
- Look for inconsistency within the same file: in this case, `debug_getRawTransaction` correctly used `encode_2718`, while `debug_getRawReceipts` in the same file did not — cross-checking sibling functions is a useful review technique.

---

### M-06 — Vote timer callback uses potentially stale timer round instead of actual vote round, causing vote misrouting

**Link:** <https://code4rena.com/reports/2025-09-monad#m-06-vote-timer-callback-uses-potentially-stale-timer-round-instead-of-actual-vote-round-causing-vote-misrouting>
When a vote timer fires, `handle_vote_timer` uses the round stored in the timer (which may be stale if consensus has advanced multiple rounds) rather than the round of the actual pending vote. This causes votes to be sent to the wrong leaders, disrupting QC formation, triggering timeouts, and degrading liveness — especially during fast network conditions or catch-up scenarios where rapid round advancement causes timers to become stale.
**Knowledge needed to catch this bug:**

- Understand that timers in fast-paced consensus protocols can become stale — by the time a timer fires, the system state may have advanced significantly. Always validate that a timer's stored context still matches the current state before acting on it.
- Distinguish between "the round this timer was scheduled for" and "the round of the thing we want to do now." These can diverge and must be derived from the actual pending data, not the timer parameter.
- Know how leader selection works in BFT consensus: sending a vote to the wrong leader (derived from a stale round) means the correct leader never receives it, which blocks QC formation and forces a timeout — a subtle but meaningful liveness degradation.

---

### M-07 — Consensus validator accepts blocks with mismatched basefee and execution `basefeepergas`

**Link:** <https://code4rena.com/reports/2025-09-monad#m-07-consensus-validator-accepts-blocks-with-mismatched-basefee-and-execution-basefeepergas>
The consensus block validator never checks that the execution header's `base_fee_per_gas` matches the consensus header's `base_fee`. A malicious proposer can deliberately diverge these two values. Consensus accepts the block (using the consensus `base_fee` for fee checks), but execution rejects it when it detects the `BaseFeeMismatch`. Since all nodes finalize the same bad block through consensus and then all fail at execution, the entire network enters a consensus/execution split that requires operator intervention to resolve.
**Knowledge needed to catch this bug:**

- In any system with separate consensus and execution layers that each maintain their own version of block metadata, always look for fields that exist in both but are never cross-validated. A missing consistency check between layers is a high-impact bug class.
- Understand that a consensus/execution split — where all nodes agree on a block that no node can execute — is one of the most severe failure modes for a blockchain, as it cannot self-heal and requires manual intervention.
- Know the EIP-1559 base fee mechanism well enough to recognize that `base_fee` drives transaction fee validation. If a proposer can forge this value in one layer without it being caught, they can manipulate which transactions appear valid to consensus while breaking execution.

---

## Low Risk Findings
>
> Note: The published report includes 2 low findings from the top QA report (Almanax). 18 additional individually submitted low findings are not publicly accessible without a Code4rena login.
---

### L-01 — HTTP Host label unsanitized → unbounded metrics cardinality

**Link:** <https://code4rena.com/reports/2025-09-monad#l-01-http-host-label-unsanitized--unbounded-metrics-cardinality-invariant-opsec>
The Prometheus/OpenTelemetry metrics pipeline takes `server.address` directly from the HTTP `Host` header without sanitization. Because any client can send an arbitrary `Host` value, this allows an attacker to inflate metrics cardinality unboundedly, which can degrade or crash observability backends and impact node performance under load.
**Knowledge needed to catch this bug:**

- Know that metrics labels derived from user-controlled input (like HTTP headers) must be normalized to a fixed, low-cardinality set. High-cardinality labels are a well-known antipattern that can overwhelm time-series databases.
- Understand that the `Host` header is fully attacker-controlled — it should never be used as a raw metrics dimension. The canonical approach is to use the server's bound local address/port instead.
- Recognize that operational security (OpSec) issues like metrics cardinality explosion can have indirect but real availability impacts, even if they don't directly compromise application logic.

---

### L-02 — JSON-RPC returns internal error details → information disclosure

**Link:** <https://code4rena.com/reports/2025-09-monad#l-02-json-rpc-returns-internal-error-details--information-disclosure-invariant-opsec>
Internal error messages from `ChainStateError::Archive` and `ChainStateError::Triedb` are included verbatim in JSON-RPC error responses returned to clients. This leaks implementation details about the node's internal storage architecture, error states, and environment, which can aid attackers in fingerprinting the system or crafting targeted exploits.
**Knowledge needed to catch this bug:**

- Apply the principle of "log internally, return generically" — detailed error information should always be written to server logs, never surfaced directly to external clients in production systems.
- Know that error message leakage is a meaningful attack enabler: internal paths, library versions, and storage layer details all narrow the attack surface an adversary needs to research.
- When auditing RPC error handling, always trace the full path from an internal error type to the client-facing response and check whether any `.to_string()` or format string propagates internal detail outward.
