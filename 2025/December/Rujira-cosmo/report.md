# Rujira — Security Audit Report

**Auditor:** han-sec
**Date:** 2025-12-16
**Platform:** Code4rena
**Report:**

---

## Contest Summary

| Item       | Detail |
|------------|--------|
| Protocol   | Rujira |
| Type       | DeFi Lending & Borrowing (CosmWasm on THORChain) |
| Language   | Rust |
| nSLOC      | 2,599 |
| Timeline   | Dec 16, 2025 – Jan 16, 2026 |

---

## Results Summary

| Severity | My Findings | Total in Report |
|----------|-------------|-----------------|
| High     | 2           | 7               |
| Medium   | 1           | 11              |
| Low      | 1           | 0               |
| **Total**| **4**       | **18**          |

---

## Table of Contents

### My Findings

### Findi

ngs I Missed
**High**

- [H-01: Unprotected Liquidation Preference Execution Allows DoS of Liquidations and Bad Debt](#h-01-unprotected-liquidation-preference-execution-allows-dos-of-liquidations-and-bad-debt)
- [H-02: Unbounded Borrower Preference Message Can DoS Liquidation](#h-02-unbounded-borrower-preference-message-can-dos-liquidation)

- [H-03: Liquidation Max Slippage Threshold Can Be Abused to Steal Liquidated Collateral](#h-03-liquidation-max-slippage-threshold-can-be-abused-to-steal-liquidated-collateral)
- [H-04: Ghost Vault `utilization()` Underflow Bricks the Vault](#h-04-ghost-vault-utilization-underflow-bricks-the-vault)
- [H-05: Account Owners Can Block Liquidations via Unbounded Gas Usage](#h-05-account-owners-can-block-liquidations-via-unbounded-gas-usage)
- [H-06: Liquidator Can Siphon Collateral From Credit Accounts on `LiquidateMsg::Repay`](#h-06-liquidator-can-siphon-collateral-from-credit-accounts-on-liquidatemsgrepay)
- [H-07: Accounts Can Prevent Being Liquidated by Moving Collateral via Preference Msgs](#h-07-accounts-can-prevent-being-liquidated-by-moving-collateral-via-preference-msgs)

**Medium**

- [M-01: Division by Zero in `adjusted_ltv()` May Block Liquidation](#m-01-division-by-zero-in-adjusted_ltv-may-block-liquidation)
- [M-02: Repayment Permanently Blocked by Rounding — "Permanent Dust Debt" DoS](#m-02-repayment-permanently-blocked-by-rounding--permanent-dust-debt-dos)
- [M-03: Incorrect Ordering in `distribute_interest` Leads to Protocol Fee Inflation](#m-03-incorrect-ordering-in-distribute_interest-leads-to-protocol-fee-inflation)
- [M-04: Interest Rate Update Without Distribution Causes Incorrect Interest Calculation](#m-04-interest-rate-update-without-distribution-causes-incorrect-interest-calculation)
- [M-05: Zero-Amount Bank Transfer Revert via Malicious Dust Repayment](#m-05-zero-amount-bank-transfer-revert-via-malicious-dust-repayment)
- [M-06: Improper Collateral Skipping on Zero USD Valuation](#m-06-improper-collateral-skipping-on-zero-usd-valuation)
- [M-08: Collateral-to-Debt Swap Slippage Check Fails to Account for Fees](#m-08-collateral-to-debt-swap-slippage-check-fails-to-account-for-fees)
- [M-09: Liquidation Order Preference Can Be Bypassed](#m-09-liquidation-order-preference-can-be-bypassed)
- [M-10: Borrower Can Avoid Protocol Fee Charge on `distribute_interest`](#m-10-borrower-can-avoid-protocol-fee-charge-on-distribute_interest)
- [M-11: Liquidation Validation Incorrectly Calculates Slippage by Ignoring Refunds](#m-11-liquidation-validation-incorrectly-calculates-slippage-by-ignoring-refunds)

---

## My Findings

---

### H-01: Unprotected Liquidation Preference Execution Allows DoS of Liquidations and Bad Debt

[Code link](https://github.com/code-423n4/2025-12-rujira/blob/88aae83b5e9d14457c3fda85634fc8d5575f75e9/contracts/rujira-ghost-credit/src/contract.rs#L265-L318)

#### Summary

`LiquidateMsg::Repay()` reverts instead of returning `SubMsg` struct. This causes the transaction to revert immediately instead of going into the `reply` block which allows user's error to continue, but revert liquidator's error.

So the user can set malicious preference msg, and cause the entire liquidation transaction to revert, essentially DOS the liquidation.

```rust
if balance.amount.is_zero() {
    // @audit NOT wrapped in SubMsg
    return Err(ContractError::ZeroDebtTokens {
        denom: balance.denom,
    });
}
```

#### Assumptions

1. Dev assumes that User's message shouldn't revert and block liquidation.

#### How can I spot this next time

1. Always think of the DEV's assumption. They assume that user's preference msg shouldn't REVERT. But this missing `SubMsg` breaks the assumption.
2. Always ask what is the dev assuming and think of ways to break their assumptions.

---

### H-02: Unbounded Borrower Preference Message Can DoS Liquidation

#### Summary

No Upper Limit on Liquidation Preference Messages.

The `set_preference_msgs` function has no validation for the number of messages:

```rust
pub fn set_preference_msgs(&mut self, msgs: Vec<LiquidateMsg>) {
    self.liquidation_preferences.messages = msgs
}
```

Every message will in turn loads all the token denom and all the vault, computationally heavy. Which leads of DOS.

#### Fix

1. Limit the number of preference message user can set.

#### How can I spot this next time

1. I should watch out for any unbounded loop. Dev's assumption is to loop through all the preference messages.
2. But borrower can set unlimited number of preference message, causing the transaction to run out of compute unit.

---

## Findings I Missed

---

## High

---

### H-03: Liquidation Max Slippage Threshold Can Be Abused to Steal Liquidated Collateral

#### Summary

The `LiquidateMsg::Execute` function didn't validate the `contract_addr` input, allowing liquidator to pass in arbitrary fund.
The attacker can then steal the borrower's fund, but still pass the validation check.

```rust
LiquidateMsg::Execute {
    contract_addr, // <@--- NO contract address validation before calling
    msg,
    funds,
} => Ok(Response::default()
    .add_submessage(
        SubMsg::reply_always(
            account.account
@>             .execute(contract_addr.clone(), msg.clone(), funds.clone())?,
            reply_id,
        )
        .with_payload(to_json_binary(&account)?),
    )
    .add_event(event_execute_liquidate_execute(
        &contract_addr,
        &msg,
        &NativeBalance(funds),
    ))),
```

#### How can I spot this next time

1. Always think of input validation, and the caller can pass any parameter.
2. DEV's assumes that the liquidator will pass in an actual DEX contract address, whereby they can pass in their own malicious address

---

### H-04: Ghost Vault `utilization()` Underflow Bricks the Vault

#### Summary

1. A malicious actor can transfer tokens to the vault address, bypassing the `deposit()` update.
2. The actor then borrows from the vault. The borrow function doesn't ensure that deposit.size() >= debt.size(), allowing the borrower to borrow more than the deposit.size() record.
3. This causes `debt.size() > deposit.size()`. Once the debt is greater than the deposit, every action which calls `utilization()` will revert due to an underflow.

```rust
// @note calculate utilization rate
pub fn utilization(&self) -> Decimal {
    // We consider accrued interest and debt in the utilization rate
    if self.deposit_pool.size().is_zero() {
        Decimal::zero()
    } else {
        // @note 1 - ((D - B) / D)
        // @note refactor to (B / D) same as AAVE
        Decimal::one()
            - Decimal::from_ratio(
                // We use the debt pool size to determine utilization
                self.deposit_pool.size().sub(self.debt_pool.size()), // <@-- underflow
                self.deposit_pool.size(),
            )
    }
}
```

#### How can I spot this next time

1. Lending protocol invariant is not checked. `deposit >= debt`.
2. DEV's assumption is the debt can never be more than deposit,
3. Using direct `sub`, instead of `checked_sub`. `checked_sub` might not completely prevent this, but at least handle the error gracefully.
4. Always think in **INVARIANT**

---

### H-05: Account Owners Can Block Liquidations via Unbounded Gas Usage

#### Summary

The `SubMsg::reply_always` didn't pass in any `gas_limit`, user can set preference message that use up all the gas, causing the transaction to revert with OOG.

```rust
LiquidateMsg::Execute {
    contract_addr,
    msg,
    funds,
} => Ok(Response::default()
    // @note adding submessage, to trigger Reply entrypoint
    .add_submessage(
        // @note always call reply entry point
        SubMsg::reply_always( // <@-- NO gas limit.
            // @note calls account execute function, which then calls the contract
            account.account.execute(
                contract_addr.clone(), // @note calls contract via user's account
                msg.clone(),           // @note msg to call
                funds.clone(),         // @note funds to transfer
            )?,
            reply_id, // @note whether user or liquidator, revert or not
        )
        // @note payload to add into the submessage
        .with_payload(to_json_binary(&account)?),
    )
    .add_event(event_execute_liquidate_execute(
        &contract_addr,
        &msg,
        &NativeBalance(funds),
    ))),
```

#### Runtime sequence

```
Cosmos SDK runtime
└── CosmWasm VM
    └── Parent contract
            └── SubMsg executes
                └── Gas-burning contract
                        └── ... consuming gas ...
                        └── GAS = 0
                        └── Cosmos SDK: OutOfGas panic ← KILLS HERE

                ✗ SubMsg never returns a result
            ✗ reply() never gets called
    ✗ CosmWasm never gets control back
✗ Cosmos SDK rolls back entire transaction
```

#### How can I spot this next time

1. DEV assumes the execution function's `SubMsg` always goes to `reply` function, didn't consider the gas usage.
2. Never give untrusted code unlimited gas inside a critical path. SubMsg::reply_always only catches application-level errors — OutOfGas happens at the Cosmos SDK layer above it and bypasses it entirely. When a submessage executes user-controlled code, always set .with_gas_limit().

---

### H-06: Liquidator Can Siphon Collateral From Credit Accounts on `LiquidateMsg::Repay`

#### Summary

1. The `LiquidateMsg::Repay(denom)` function loads the token denom, but didn't check whether a credit account has debt in that token denom

```rust
    // @audit query its balance but didn't check whether has debt in this denom
    let balance = deps.querier.query_balance(account.id(), &denom)?;
```

1. Attacker can repay non-debt token, and earn fees.

#### Fix

1. Validate that the account actually has that debt.

#### How can I spot this next time

1. DEV assumed liquidator will only repay debt token. Without checking whether the user has debt in that token, liquidator can `pretend` to liquidate and earn fees.
2. Must confirm liquidator only can repay account with actual debt token.

---

### H-07: Accounts Can Prevent Being Liquidated by Moving Collateral via Preference Msgs

#### Summary

1. User can set `PreferenceMSg::Execute` to swap collateral away, making it insolvent, no liquidator can rescued, thus DOS liquidation

#### Assumptions

1. DEV assumes user's can't make their ltv so bad that any liquidation is unrecoverable, and didn't consider the angle of collateral being swapped away.

#### How can I spot this next time

1. When looking at what can DOS liquidation, my thinking of user can make it too safe is correct. But I should consider that user can make it too bad that it can't be recovered.
2. Explore all the possible ways to DOS an important function.

---

## Medium

---

### M-01: Division by Zero in `adjusted_ltv()` May Block Liquidation

#### Summary

1. During `Liquidation`, `adjusted_ltv` can panic with `division by 0`, if the swapped collateral is not listed(tracked). Hence, `collateral == 0`.
2. User can set a malicious `PreferenceMsg` collateral to non-registered collateral. In the subsequent `DoLiquidate()` call, `adjusted_ltv` will panic.

```rust
debt.div(collateral)
```

#### Assumptions

1. An accoount with debt will always have registered collateral. This breaks when user intentionally swap for non-registered collateral.
2. Dev didn't account `collateral == 0` and causes `debt.div(collateral)` to panic

#### How can I spot this next time

1. Pay attention to any division, underflow/overflow, think of any way to cause panic.

---

### M-02: Repayment Permanently Blocked by Rounding — "Permanent Dust Debt" DoS

#### Summary

1. The pool state after interest accrual, eg:

```rust
debt_pool: size=10, shares=7 → 1 share = 1.4285 tokens
Alice: 1 share remaining
```

1. Issue with the clamping `min(user_input, calculated_value)` to prevent overpaying, but also limit user's capability to completely repay everything
2. The deadlock:

```rust
"How much does Alice owe?"     → floor(10 * 1 / 7) = 1 token
"Clamp repayment to debt"      → Alice can only pay 1 token
"How many shares does 1 burn?" → floor(1* 7 / 10) = 0 shares
"Burn 0 shares"                → REVERT
```

#### Assumptions

1. Shares and Token calculation rounding down favouring the protocol, that's the correct design. However, coupled up with a clamping function, which takes the `min(user_input, calculated_value)`. When user only left dust, that gets rounded down, so `calculated_value` is always lower.

#### How can I spot this next time

1. Always map all conversions and their rounding directions.
2. Trace round-trip: 1 share → tokens → shares. Get back to 1?
3. Whether function handles dust amount well.

---

### M-03: Incorrect Ordering in `distribute_interest` Leads to Protocol Fee Inflation

#### Summary

1. Quick breakdown- `deposit` only adds to `size`, but not the `shares(raw unit)`.
2. In the `distribute_interest` function, `join(protocol_interest)` is called first before accruing interest to all lenders.
3. This means protocol get to participate before accruing interest. Allowing protocol to earn higher interest, and diluting the fee for the lender.
4. Meaning protocol earn interest retroactively

```rust
self.join => self.deposit
```

#### Assumptions

1. Dev didn't consider the sequence of `settle` before any new changes.
2. Any fee accrual should be done first before adding new deposit.

---

### M-04: Interest Rate Update Without Distribution Causes Incorrect Interest Calculation

#### Summary

1. `sudo::SetInterest` function didn't not distribute interest first before changing the rate. Past interest is being calculated retroactively using new rate.

```rust
pub fn sudo(deps, _env, msg) {          // ← note: _env (unused!)
    let mut config = Config::load(deps.storage)?;

    // ❌ no distribute_interest() call
    // ❌ no state loaded at all

    match msg {
        SudoMsg::SetInterest(interest) => {
            config.interest = interest;   // ← overwrites directly
            config.save(deps.storage)?;
        }
    }
}
```

#### Fix

1. Clear the interest first, before changing `interest_rate`.

#### Assumptions

1. Assumes that key function such as `execute()` settles interest first, but didn't consider the `SetInterest()`. While it didn't change state but it changes the `interest_rate` without settling it first.

#### How can I spot this next time

1. Have a mapping of all the states, and which function could change it.
2. Anything that affecting state should be settled first, when it comes to interest.

---

### M-05: Zero-Amount Bank Transfer Revert via Malicious Dust Repayment

#### Summary

1. Borrower can set `PerferenceMsg` to swap dust amount, which got rounded to 0

---

### M-06: Improper Collateral Skipping on Zero USD Valuation

#### Summary

1. Collateral tokens with zero USD oracle price are silently skipped during account health check. This can undervalue a position if a collateral token temporarily loses its oracle feed.
2. This leads to `unjustified` liquidation.

```rust
if item.value_usd(deps.querier)?.is_zero() {
    continue;
}
```

#### Assumptions

1. Dev assuming better to skip a collateral than using bad oracle price.
2. But skipping the collateral can create another issue, which is position might be underwater unnecessarily.

#### How can I spot this next time

1. Check for `Silent handling of suspicious external data` is almost always a bug in financial code.
2. Watch out for any silent handling of collateral and debt.

---

### M-08: Collateral-to-Debt Swap Slippage Check Fails to Account for Fees

#### Summary

1. `validate_liquidation` slippage check can fail due to fees deduction
2. Liquidator `spend_usd` but the actual `repaid_usd`

```rust
slippage = (spent_usd - repaid_usd) / spent_usd
```

#### Assumptions

1. Dev assuming slippage check correctly measure slippage during DEX swap, but failed to realize the fee deduction.

#### How can I spot this next time

1. Ensure what it included in the calculation and what is not.
2. Ask what does the slippage check, what deviates the value, by right the slippage is only for DEX slippage, not the fees.

---

### M-09: Liquidation Order Preference Can Be Bypassed

#### Summary

1. Liquidator doesn't need to follow user's collateral preference, as long as they satisfied the last check.
2. The `validate_liquidate` checks every msg, but it will continue even with `Error` as long as there is still message in the transaction.

```rust
let check = account
    .check_safe(&config.liquidation_threshold)          // LTV check
    .and_then(|_| account.check_unsafe(&config.adjustment_threshold))  // over-liquidation check
    .and_then(|_| account.validate_liquidation(...))    // preference order + slippage

match (queue.pop(), check) {
    (_, Ok(())) => done,
    (None, Err(err)) => revert,
    (Some(msg), Err(_)) => continue executing,  // ← ALL errors ignored
}
```

#### Assumptions

1. Dev assumes the error will be captured accordingly, but because the match arm is an all in one error capture, so it continue executing even when certain rules were violated.

#### How can I spot this next time

1. Understand what error each check produces, and whether that particular check is being handled accordingly.

---

### M-10: Borrower Can Avoid Protocol Fee Charge on `distribute_interest`

#### Summary

1. The vault charges borrowers interest + protocol fee by increasing `debt_pool.size`. But when the protocol fee is too small to mint deposit pool shares, the code sets `fee = 0` before charging the debt pool. Borrowers' debt only increases by interest, never the fee.

```rust
self.debt_pool.deposit(interest.add(fee))?;
```

#### Assumptions

1. Dev only thinks of handling fee == 0 issue but didn't think of the flow of charging the borrower.

#### How can I spot this next time

1. When you see one operation's failure affecting an unrelated operation, that's a bug.

The pattern:

```rust
try operation A (mint shares)
  if A fails → set shared_variable = 0
operation B uses shared_variable (charge debt)
```

---

### M-11: Liquidation Validation Incorrectly Calculates Slippage by Ignoring Refunds

#### Summary

1. Liquidator swaps some collateral → gets debt tokens in the credit account
2. Repay sends everything to vault
3. Vault takes only what's owed, refunds excess
4. The excess debt tokens sitting in the credit account still have value — they should count as **collateral** for the post-liquidation LTV check

```rust
    fn sent(&self, new: &Self) -> Self {
        let mut spent = self.clone();
        // @note comparing old value and new value. See how much does an old value decreases vs
        for coin in new.clone().into_vec() {
            // Swallow the error with a NOOP if we have received a new token,
            // which will try and subtract the new from the original balance where it doesn't exist
            spent = spent.clone().sub_saturating(coin).unwrap_or(spent.clone()) // <@--- doesn't cater for refund
        }
        spent
    }
```

#### Assumptions

1. The slippage check is design with only for collateral protection, but it wasn't designed for if any token is refuned back to the credit account

#### How can I spot this next time

1. Ask `"Is the flow one-way, or does value come back?"`, if value should come back check if the round trip is supported.
