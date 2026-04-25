# Rujira Audit Contest — Validated Findings Report

## Table of Contents

### High Severity

- [H-01: Unprotected Liquidation Preference Execution Allows DoS of Liquidations and Bad Debt](#h-01-unprotected-liquidation-preference-execution-allows-dos-of-liquidations-and-bad-debt)
- [H-02: Ghost Credit Liquidations Pay the "Liquidator Fee" to the Contract, Not the Liquidator](#h-02-ghost-credit-liquidations-pay-the-liquidator-fee-to-the-contract-not-the-liquidator)
- [H-03: Ghost Vault utilization() Underflow Bricks the Vault](#h-03-ghost-vault-utilization-underflow-bricks-the-vault)
- [H-04: Liquidation DoS via Unbounded Recursion](#h-04-liquidation-dos-via-unbounded-recursion)
- [H-05: Liquidator Can Siphon Collateral From Credit Accounts on LiquidateMsg::Repay](#h-05-liquidator-can-siphon-collateral-from-credit-accounts-on-liquidatemsgrepay)
- [H-06: Borrower Preferences Can Force Deterministic Reverts and Permanently Block Liquidation](#h-06-borrower-preferences-can-force-deterministic-reverts-and-permanently-block-liquidation)
- [H-07: Account Owners Can Block Liquidations via Unbounded Gas Usage](#h-07-account-owners-can-block-liquidations-via-unbounded-gas-usage)
- [H-08: Accounts Can Prevent Being Liquidated by Moving Collateral via Preference Msgs](#h-08-accounts-can-prevent-being-liquidated-by-moving-collateral-via-preference-msgs)
- [H-09: Liquidation Max Slippage Threshold Can Be Abused to Steal Liquidated Collateral](#h-09-liquidation-max-slippage-threshold-can-be-abused-to-steal-liquidated-collateral)

### Medium Severity

- [M-01: Division by Zero in adjusted_ltv() May Block Liquidation](#m-01-division-by-zero-in-adjusted_ltv-may-block-liquidation)
- [M-02: Repayment Permanently Blocked by Rounding — "Permanent Dust Debt" DoS](#m-02-repayment-permanently-blocked-by-rounding--permanent-dust-debt-dos)
- [M-03: Incorrect Ordering in distribute_interest Leads to Protocol Fee Inflation](#m-03-incorrect-ordering-in-distribute_interest-leads-to-protocol-fee-inflation)
- [M-04: Interest Rate Update Without Distribution Causes Incorrect Interest Calculation](#m-04-interest-rate-update-without-distribution-causes-incorrect-interest-calculation)
- [M-05: Zero-Amount Bank Transfer Revert via Malicious Dust Repayment](#m-05-zero-amount-bank-transfer-revert-via-malicious-dust-repayment)
- [M-06: Improper Collateral Skipping on Zero USD Valuation](#m-06-improper-collateral-skipping-on-zero-usd-valuation)
- [M-07: Vault Repay Refunds Excess Funds to info.sender Instead of Credit Account](#m-07-vault-repay-refunds-excess-funds-to-infosender-instead-of-credit-account)
- [M-08: Collateral-to-Debt Swap Slippage Check Fails to Account for Fees](#m-08-collateral-to-debt-swap-slippage-check-fails-to-account-for-fees)
- [M-09: Liquidation Order Preference Can Be Bypassed](#m-09-liquidation-order-preference-can-be-bypassed)
- [M-10: Borrower Can Avoid Protocol Fee Charge on distribute_interest](#m-10-borrower-can-avoid-protocol-fee-charge-on-distribute_interest)
- [M-11: Liquidation Validation Incorrectly Calculates Slippage by Ignoring Refunds](#m-11-liquidation-validation-incorrectly-calculates-slippage-by-ignoring-refunds)

### Low Severity

- [L-01: Liquidation Accounting Ignores Non-Collateral Balances](#l-01-liquidation-accounting-ignores-non-collateral-balances)
- [L-02: Incorrect ExecuteMsg Funds Handling Causes Failed Deposits](#l-02-incorrect-executemsg-funds-handling-causes-failed-deposits)
- [L-03: Migration Version Check Missing](#l-03-migration-version-check-missing)
- [L-04: Governance SetVault Overwrites BORROW Mapping, Ignoring Existing Debt](#l-04-governance-setvault-overwrites-borrow-mapping-ignoring-existing-debt)
- [L-05: Missing Slippage Protection on Deposits and Borrows Enables Sandwiching](#l-05-missing-slippage-protection-on-deposits-and-borrows-enables-sandwiching)
- [L-06: Vault Fee and Fee Address Cannot Be Updated After Instantiation](#l-06-vault-fee-and-fee-address-cannot-be-updated-after-instantiation)
- [L-07: Last LP to Withdraw Bears the Whole Deficit-Loss in Case of Bad Debt](#l-07-last-lp-to-withdraw-bears-the-whole-deficit-loss-in-case-of-bad-debt)

---

## Summary

| Severity | Count |
|----------|-------|
| High     | 9     |
| Medium   | 11    |
| Low      | 7     |
| **Total** | **27** |

---

## High Severity

### H-01: Unprotected Liquidation Preference Execution Allows DoS of Liquidations and Bad Debt

| Field | Value |
|-------|-------|
| **ID** | F-1 |
| **Primary** | S-1025 by 8di4k |
| **Duplicates** | 114 |
| **Status** | Fixed |
| **Affected Code** | [contract.rs#L265-L318](https://github.com/code-423n4/2025-12-rujira/blob/main/contracts/rujira-ghost-credit/src/contract.rs#L265-L318), [contract.rs#L77-L87](https://github.com/code-423n4/2025-12-rujira/blob/main/contracts/rujira-ghost-credit/src/contract.rs#L77-L87) |

**Description:**
Attackers can make their credit accounts permanently unliquidatable by exploiting the lack of error isolation in `LiquidateMsg::Repay` preference handling. While `LiquidateMsg::Execute` uses `SubMsg::reply_always` to catch errors, `LiquidateMsg::Repay` does not — errors propagate and fail the entire transaction. Combined with user preferences executing before liquidator messages, attackers can inject failing messages (e.g., zero-balance repay or invalid vault denom) that block all liquidation attempts.

**Impact:**
Unbounded bad debt accumulation and protocol insolvency, as unsafe positions cannot be liquidated even when LTV exceeds thresholds. Attack cost is minimal (only gas fees) and can be applied to unlimited accounts.

---

### H-02: Ghost Credit Liquidations Pay the "Liquidator Fee" to the Contract, Not the Liquidator

| Field | Value |
|-------|-------|
| **ID** | F-3 |
| **Primary** | S-277 by legat |
| **Duplicates** | 83 |
| **Status** | Fixed |
| **Affected Code** | [contract.rs#L73-L111](https://github.com/code-423n4/2025-12-rujira/blob/main/contracts/rujira-ghost-credit/src/contract.rs#L73-L111), [contract.rs#L281-L318](https://github.com/code-423n4/2025-12-rujira/blob/main/contracts/rujira-ghost-credit/src/contract.rs#L281-L318) |

**Description:**
Liquidation execution is routed through an internal self-call to `ExecuteMsg::DoLiquidate`. Since `DoLiquidate` enforces `info.sender == contract_address`, the repayment step pays the liquidator fee to `info.sender` — the Ghost Credit contract itself rather than the external liquidator who initiated the liquidation.

**Impact:**
Systematic misallocation of liquidation rewards breaks the protocol's incentive mechanism. During periods of price volatility, liquidation activity is critical; if liquidators are not paid, the protocol may become insolvent.

---

### H-03: Ghost Vault utilization() Underflow Bricks the Vault

| Field | Value |
|-------|-------|
| **ID** | F-6 |
| **Primary** | S-179 by legat |
| **Duplicates** | 76 |
| **Status** | Fixed |
| **Affected Code** | [state.rs#L83](https://github.com/code-423n4/2025-12-rujira/blob/main/contracts/rujira-ghost-vault/src/state.rs#L83), [contract.rs#L116-L141](https://github.com/code-423n4/2025-12-rujira/blob/main/contracts/rujira-ghost-vault/src/contract.rs#L116-L141) |

**Description:**
The vault computes utilization using `deposit_pool.size() - debt_pool.size()` with `Uint128::sub`, which panics on underflow. A permissionless native transfer ("donation") increases the vault's bank balance without updating `deposit_pool.size()`. A borrower can then borrow against this extra bank balance, pushing `debt_pool.size()` above `deposit_pool.size()`. Since `distribute_interest()` is called before every execute/query entry point, the vault becomes permanently bricked.

**Impact:**
Permanent / critical DoS of the vault. All funds become operationally frozen — users cannot deposit, withdraw, repay, or borrow. Even simple queries fail.

---

### H-04: Liquidation DoS via Unbounded Recursion

| Field | Value |
|-------|-------|
| **ID** | F-11 |
| **Primary** | S-1431 by ElmInNyc99 |
| **Duplicates** | 79 |
| **Status** | Fixed |
| **Affected Code** | [account.rs#L231-L233](https://github.com/code-423n4/2025-12-rujira/blob/main/contracts/rujira-ghost-credit/src/account.rs#L231-L233) |

**Description:**
There is no limit on the number of preference messages a user can set via `set_preference_msgs`. During liquidation, all liquidator and user preference messages are combined into a single queue processed recursively — each iteration performs an expensive `CreditAccount::load()` with external queries for every collateral and vault. A user can set hundreds of preference messages causing gas exhaustion or stack overflow.

**Impact:**
Account DoS making positions impossible to liquidate. Bad debt will accumulate as collateral prices drop because the system cannot recover funds through liquidation. No fallback mechanism exists to bypass user preference messages.

---

### H-05: Liquidator Can Siphon Collateral From Credit Accounts on LiquidateMsg::Repay

| Field | Value |
|-------|-------|
| **ID** | F-69 |
| **Primary** | S-335 by hecker_trieu_tien |
| **Duplicates** | 13 |
| **Status** | Fixed |
| **Affected Code** | [contract.rs#L265](https://github.com/code-423n4/2025-12-rujira/blob/main/contracts/rujira-ghost-credit/src/contract.rs#L265) |

**Description:**
The repayment logic in `LiquidateMsg::Repay` loads the vault from a caller-supplied denom without verifying the account has outstanding debt for that denom. It sends the account's entire balance and pays fees to the liquidator before the vault validates the repayment. If the vault rejects or refunds the over-repayment (e.g., zero debt), the liquidator has already received their fee percentage. A malicious liquidator can pair one legitimate repayment with one fraudulent repay to stay under slippage checks.

**Impact:**
Liquidators can extract a configurable percentage of any collateral denom that has a vault entry, leaving victims with permanently locked balances while protocol fees are misdirected.

---

### H-06: Borrower Preferences Can Force Deterministic Reverts and Permanently Block Liquidation

| Field | Value |
|-------|-------|
| **ID** | F-158 |
| **Primary** | S-326 by 4Nescient |
| **Duplicates** | 12 |
| **Affected Code** | [contract.rs#L110-L117](https://github.com/code-423n4/2025-12-rujira/blob/main/contracts/rujira-ghost-credit/src/contract.rs#L110-L117), [contract.rs#L272-L276](https://github.com/code-423n4/2025-12-rujira/blob/main/contracts/rujira-ghost-credit/src/contract.rs#L272-L276) |

**Description:**
Three distinct preference patterns guarantee that `DoLiquidate` never reaches the success state:

1. **Zero-balance repay:** The owner registers `Repay(<denom>)` but keeps zero of that denom — immediate `ZeroDebtTokens` error.
2. **Over-repay:** The owner pre-funds the account so the preference fully repays the vault — LTV drops below adjustment threshold triggering `ContractError::Safe`.
3. **Slippage violation:** The owner's preference performs a value-losing swap causing `LiquidationMaxSlipExceeded`.

All three paths revert outside the `SubMsg` context, so the reply callback that should ignore preference errors never triggers.

**Impact:**
Protocol insolvency — owners can permanently block liquidation. Bad debt accumulates endlessly and lenders cannot recover funds.

---

### H-07: Account Owners Can Block Liquidations via Unbounded Gas Usage

| Field | Value |
|-------|-------|
| **ID** | F-159 |
| **Primary** | S-301 by hecker_trieu_tien |
| **Duplicates** | 8 |
| **Affected Code** | [contract.rs#L319](https://github.com/code-423n4/2025-12-rujira/blob/main/contracts/rujira-ghost-credit/src/contract.rs#L319) |

**Description:**
The contract dispatches every preference `LiquidateMsg::Execute` via `SubMsg::reply_always` without a `gas_limit`. Since preferences execute before the liquidator's route, a malicious borrower can register a gas-exhausting preference that consumes the entire transaction gas budget. An `OutOfGas` inside the submessage prevents the runtime from emitting a reply, so the error-ignoring handler never runs and the whole liquidation transaction rolls back.

**Impact:**
Borrowers can make their underwater positions impossible to liquidate, leaving the protocol with stuck bad debt equal to the borrower's outstanding liabilities.

---

### H-08: Accounts Can Prevent Being Liquidated by Moving Collateral via Preference Msgs

| Field | Value |
|-------|-------|
| **ID** | F-160 |
| **Primary** | S-898 by cccz |
| **Duplicates** | 5 |
| **Affected Code** | [contract.rs#L319-L338](https://github.com/code-423n4/2025-12-rujira/blob/main/contracts/rujira-ghost-credit/src/contract.rs#L319-L338) |

**Description:**
An account owner can set a `PreferenceMsg::Execute` that transfers collateral out of the account to an arbitrary contract during liquidation. Since preferences run first, the account becomes insolvent (LTV permanently > 1) because its debt exceeds remaining collateral. An insolvent account cannot satisfy the post-liquidation LTV requirement of being between `adjustment_threshold` and `liquidation_threshold`, making it permanently unliquidatable. This is distinct from F-1 since the Execute preference *succeeds* — it deliberately drains value.

**Impact:**
Permanent liquidation immunity for malicious borrowers, causing irrecoverable bad debt.

---

### H-09: Liquidation Max Slippage Threshold Can Be Abused to Steal Liquidated Collateral

| Field | Value |
|-------|-------|
| **ID** | F-162 |
| **Primary** | S-585 by bbl4de |
| **Duplicates** | 10 |
| **Affected Code** | [contract.rs#L319-L339](https://github.com/code-423n4/2025-12-rujira/blob/main/contracts/rujira-ghost-credit/src/contract.rs#L319-L339) |

**Description:**
`LiquidateMsg::Execute` allows arbitrary contract calls funded by the credit account without validating what tokens are moved and where. The contract only checks net slippage (collateral spent vs. debt repaid). A malicious liquidator can submit two `Execute` messages: one that drains collateral to themselves via a helper contract, and another that performs a legitimate swap to fix the LTV. The stolen value remains within the `liquidation_max_slip` tolerance, so the liquidation succeeds.

**Impact:**
Direct theft of collateral proportional to the `liquidation_max_slip` value multiplied by the size of the liquidated collateral. Attack is repeatable for every qualifying liquidation.

---

## Medium Severity

### M-01: Division by Zero in adjusted_ltv() May Block Liquidation

| Field | Value |
|-------|-------|
| **ID** | F-5 |
| **Primary** | S-900 by cccz |
| **Duplicates** | 112 |
| **Affected Code** | [account.rs#L152-L176](https://github.com/code-423n4/2025-12-rujira/blob/main/contracts/rujira-ghost-credit/src/account.rs#L152-L176) |

**Description:**
In `adjusted_ltv()`, if all collateral values evaluate to zero (e.g., during multi-step swaps where intermediate tokens are not registered collateral, or via preference msgs swapping to non-collateral tokens), the function divides debt by zero collateral, causing a panic that blocks the entire liquidation process. Account owners can exploit this by setting preference messages that exchange account tokens for non-collateral tokens.

**Impact:**
Liquidation blockage leading to bad debt accumulation. Particularly problematic for multi-step liquidation routes requiring intermediate tokens.

---

### M-02: Repayment Permanently Blocked by Rounding — "Permanent Dust Debt" DoS (INTERESTING TO SHARE)

| Field | Value |
|-------|-------|
| **ID** | F-7 |
| **Primary** | S-1411 by I1iveF0rTh1Sh1t |
| **Status** | Fixed |

**Description:**
After interest accrual causes the debt pool ratio `size/shares` to become non-integer, repay logic clamps the internal repay amount to `floor(size/shares)` (the borrower's debt). Burning even one remaining debt share requires `ceil(size/shares)`. Because the contract clamps to the floored value and refunds the remainder, the share burn calculation yields 0 shares and reverts, making full repayment impossible.

**Impact:**
Permanent dust debt that can never be repaid, leaving accounts in perpetually indebted state and preventing clean closure.

---

### M-03: Incorrect Ordering in distribute_interest Leads to Protocol Fee Inflation

| Field | Value |
|-------|-------|
| **ID** | F-31 |
| **Primary** | S-359 by 0x37 |
| **Status** | Fixed |

**Description:**
In `distribute_interest`, protocol fee shares are minted *before* the deposit pool size is increased by accrued interest. This means the protocol fee is minted at a cheaper share price (pre-interest), resulting in more shares than intended being allocated to the protocol — inflating protocol fees and diluting supplier yields.

**Impact:**
Protocol over-collects fees at the expense of depositors/suppliers who receive less yield than they are owed.

---

### M-04: Interest Rate Update Without Distribution Causes Incorrect Interest Calculation

| Field | Value |
|-------|-------|
| **ID** | F-47 |
| **Primary** | S-412 by cholakov |
| **Status** | Fixed |

**Description:**
The `sudo::SetInterest` function allows the admin to change interest rate parameters without first distributing accrued interest. Historical interest is then retroactively calculated using the new rate instead of the rate active when debt actually accrued. The admin has no direct way to call `distribute_interest()` — it is only callable internally by the contract.

**Impact:**
Material loss of funds for either depositors or borrowers depending on whether rates are increased or decreased. This is not admin error — it is a systematic design flaw in the only available rate-change mechanism.

---

### M-05: Zero-Amount Bank Transfer Revert via Malicious Dust Repayment

| Field | Value |
|-------|-------|
| **ID** | F-61 |
| **Primary** | S-373 by 0x37 |
| **Status** | Fixed |

**Description:**
When the remaining debt token balance in a credit account is dust (e.g., 1 wei), the liquidator fee calculation rounds down to zero (`1 wei * 0.5% = 0`). Cosmos `BankMsg::Send` does not support zero-amount transfers and will revert the transaction. A malicious credit account owner can leave 1 wei of debt token and add a `Repay` preference message, causing all liquidation attempts to fail.

**Impact:**
Liquidation DoS via dust amounts, blocking recovery of unsafe positions.

---

### M-06: Improper Collateral Skipping on Zero USD Valuation

| Field | Value |
|-------|-------|
| **ID** | F-74 |
| **Primary** | S-558 by Tigerfrake |
| **Severity** | Informative / Valid |

**Description:**
Collateral tokens with zero USD oracle price are silently skipped during account evaluation. This can undervalue a position if a collateral token temporarily loses its oracle feed, and affects liquidation calculations by underestimating the true collateral backing of a position.

**Impact:**
Incorrect account valuations during oracle edge cases; potential for unjustified liquidations or missed liquidation triggers.

---

### M-07: Vault Repay Refunds Excess Funds to info.sender Instead of Credit Account

| Field | Value |
|-------|-------|
| **ID** | F-87 |
| **Primary** | S-273 by lian886 |
| **Status** | Fixed |

**Description:**
The vault's `MarketMsg::Repay` refunds any excess payment (`amount - repay_amount`) to `info.sender`. In the ghost-credit integration, the vault is called by the ghost-credit contract (not the borrower's credit account directly), so refunds are misdirected to the ghost-credit contract rather than returned to the borrower's credit account.

**Impact:**
Loss of funds for credit accounts on any over-repayment scenario. Refunded funds become stuck in the ghost-credit registry contract.

---

### M-08: Collateral-to-Debt Swap Slippage Check Fails to Account for Fees

| Field | Value |
|-------|-------|
| **ID** | F-95 |
| **Primary** | S-1058 by bbl4de |
| **Status** | Fixed |

**Description:**
The post-liquidation slippage check compares collateral USD value spent vs. debt USD value repaid, but does not account for the liquidation fee and liquidator fee deducted during the `Repay` step. The effective slippage is always higher than what the check calculates by the sum of both fee percentages. This allows liquidations with actual slippage exceeding the configured `liquidation_max_slip`.

**Impact:**
Weaker slippage protection than configured, causing more value loss for liquidated account owners than intended.

---

### M-09: Liquidation Order Preference Can Be Bypassed

| Field | Value |
|-------|-------|
| **ID** | F-99 |
| **Primary** | S-594 by ewah |
| **Status** | Fixed |

**Description:**
The liquidation order preference enforcement uses only a final remaining balance snapshot to verify that the borrower's preferred collateral ordering was respected. This snapshot-based approach doesn't capture intermediate execution order, allowing a liquidator to structure their messages to bypass the intended preference ordering while still satisfying end-state checks.

**Impact:**
Account owners' liquidation preferences are not honored, violating protocol invariants and potentially causing worse outcomes for borrowers.

---

### M-10: Borrower Can Avoid Protocol Fee Charge on distribute_interest

| Field | Value |
|-------|-------|
| **ID** | F-151 |
| **Primary** | S-311 by hecker_trieu_tien |
| **Status** | Fixed |

**Description:**
A borrower can structure transactions to avoid paying the protocol fee portion of interest by exploiting the timing of `distribute_interest` calls, reducing protocol revenue.

**Impact:**
Revenue loss for the protocol as borrowers can systematically avoid fee payments.

---

### M-11: Liquidation Validation Incorrectly Calculates Slippage by Ignoring Refunds

| Field | Value |
|-------|-------|
| **ID** | F-156 |
| **Primary** | S-1468 by 0xkrodhan |

**Description:**
The `validate_liquidation` function calculates slippage based on collateral spent and debt repaid, but fails to account for assets refunded by the vault during repayment. When the vault clamps repayment to actual debt and refunds the excess, the refunded amount is not credited back in the slippage calculation, leading to false-positive slippage violations.

**Impact:**
Valid liquidations are incorrectly reverted due to overstated slippage calculations, potentially leaving unsafe positions unliquidated.

---

## Low Severity

### L-01: Liquidation Accounting Ignores Non-Collateral Balances

| Field | Value |
|-------|-------|
| **ID** | F-15 |
| **Primary** | S-1007 by 0xAsen |
| **Severity** | Informative / Valid |

**Description:**
Non-collateral token balances held in a credit account are not tracked in liquidation accounting. During a liquidation, these balances can potentially be extracted by a liquidator without being reflected in the slippage or value-spent calculations.

**Impact:**
Potential for unauthorized extraction of non-collateral assets during liquidation events.

---

### L-02: Incorrect ExecuteMsg Funds Handling Causes Failed Deposits

| Field | Value |
|-------|-------|
| **ID** | F-48 |
| **Primary** | S-310 by hecker_trieu_tien |
| **Status** | Fixed |

**Description:**
The funds attached to `ExecuteMsg::Account` are not properly forwarded to the credit account during deposit operations, causing transactions to fail unexpectedly.

**Impact:**
User-facing transaction failures when attempting to deposit funds into credit accounts.

---

### L-03: Migration Version Check Missing

| Field | Value |
|-------|-------|
| **ID** | F-46 |
| **Primary** | S-195 by gegul |
| **Status** | Fixed |

**Description:**
The contract migration entry point does not validate the version being migrated from/to, potentially allowing downgrades or repeated migrations that could corrupt state.

**Impact:**
Risk of state corruption via improper migration sequences.

---

### L-04: Governance SetVault Overwrites BORROW Mapping, Ignoring Existing Debt

| Field | Value |
|-------|-------|
| **ID** | F-49 |
| **Primary** | S-529 by lian886 |
| **Status** | Fixed |

**Description:**
The governance `SetVault` sudo call overwrites the vault entry in the `BORROW` mapping without checking for existing debt in the old vault. Outstanding debt in the old vault becomes untracked, potentially enabling collateral withdrawal and protocol insolvency.

**Impact:**
Risk of protocol insolvency if a vault is replaced while borrowers have outstanding debt in the old vault.

---

### L-05: Missing Slippage Protection on Deposits and Borrows Enables Sandwiching

| Field | Value |
|-------|-------|
| **ID** | F-129 |
| **Primary** | S-1114 by calc1f4r |
| **Status** | Disputed / Valid |

**Description:**
Deposits and borrows in the vault do not include slippage protection parameters, making them susceptible to sandwich attacks that can extract value from users by manipulating share prices before and after user transactions.

**Impact:**
Value extraction from depositors and borrowers via MEV sandwich attacks.

---

### L-06: Vault Fee and Fee Address Cannot Be Updated After Instantiation

| Field | Value |
|-------|-------|
| **ID** | F-133 |
| **Primary** | S-1118 by ZanyBonzy |
| **Status** | Fixed |

**Description:**
Once the vault is instantiated, the protocol fee rate and fee collection address cannot be updated through any governance or admin mechanism, limiting operational flexibility for the protocol.

**Impact:**
Inability to adjust fee parameters or change the fee recipient address after deployment.

---

### L-07: Last LP to Withdraw Bears the Whole Deficit-Loss in Case of Bad Debt

| Field | Value |
|-------|-------|
| **ID** | F-142 |
| **Primary** | S-501 by Tigerfrake |
| **Severity** | Informative / Valid |

**Description:**
In the event of bad debt, share-based accounting does not distribute losses proportionally until realized. The last liquidity provider to withdraw from the vault absorbs the entire deficit as their shares represent a claim on assets that no longer exist.

**Impact:**
Unfair loss distribution — the last LP to exit takes a disproportionately large loss while earlier withdrawers exit whole.

---

## Liquidation DoS Attack Surface Summary

All seven findings exploit the borrower-controlled preference mechanism to permanently block liquidation:

| Finding | Severity | How it DoS liquidations |
|---------|----------|------------------------|
| **H-01** | High | Preference `Repay` with invalid denom — error propagates (not in SubMsg) |
| **H-04** | High | Hundreds of preference messages — gas exhaustion / stack overflow |
| **H-06** | High | Preference `Repay` with zero balance, over-repay, or slippage violation — error propagates |
| **H-07** | High | Preference `Execute` with gas-exhausting contract — `OutOfGas` before reply handler |
| **H-08** | High | Preference `Execute` transfers collateral out — insolvency — LTV check impossible |
| **M-01** | Medium | Preference swaps to non-collateral token — `adjusted_ltv()` divides by zero |
| **M-05** | Medium | Preference creates dust balance — fee rounds to 0 — `BankMsg::Send(0)` reverts |

**Common root cause:** The borrower controls code (preferences) that executes during their own liquidation, with insufficient isolation between preference execution and the liquidation outcome.

**Common fix:** Wrap all preference execution in properly gas-limited SubMsgs, whitelist callable contract addresses, and guard against zero-amount edge cases.

---

## Reusable Prompt for Future Audits

```
Navigate to the Code4rena audit submissions page at [PASTE_URL_HERE].
Extract all valid primary findings (High, Medium, and Low severity).
For each finding, collect: the finding ID, severity, title, primary submission ID,
author, fix status, number of duplicates, and a concise summary of the vulnerability.

Then compile everything into a single structured Markdown file and download it.
The file should follow the Code4rena report format, including:

1. A Table of Contents with anchor links organized by severity
   (High -> Medium -> Low), using [H-XX], [M-XX], [L-XX] numbering.
2. A Summary table with severity counts.
3. For each finding: a metadata table (ID, Primary, Duplicates, Status,
   Affected Code), a Description section (2-4 sentences on the vulnerability),
   and an Impact section (1-2 sentences on consequences).

Filter the submissions page to "Primary submissions" to get unique findings.
Only include findings marked as Valid by the judge (skip Invalid, Spam, Out of Scope).
Sort findings by severity (High first, then Medium, then Low).
Download the result as a .md file.
```
