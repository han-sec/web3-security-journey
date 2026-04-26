# Olas — Security Audit Report

**Auditor:** han-sec
**Date:** 2026-01
**Platform:** TBD

---

## Contest Summary

| Item | Detail |
|------|--------|
| Protocol | Olas |
| Type | TBD |
| Language | TBD |
| Total Prize Pool | TBD |
| Start Date | TBD |
| End Date | TBD |

---

## Results Summary

| Severity | Total | Found by Me |
|----------|-------|-------------|
| High     | 11    | 0           |
| Medium   | 10    | 1           |
| Low      | 0     | 0           |

---

## Table of Contents

### My Findings

| ID | Title | Severity |
|----|-------|----------|
| [M-11](#m-11) | Price Cumulative Last Is Used Inverted in Uniswap Oracle | Medium |

### Findings I Missed

#### High

| ID | Title |
|----|-------|
| [H-01](#h-01) | Variable Overwrite Makes Deviation Check Useless |
| [H-02](#h-02) | Incorrect TWAP Calculation in `BalancerPriceOracle` Allows Price Manipulation |
| [H-03](#h-03) | Insolvency via Cross-Service Reentrancy in `StakingBase._withdraw` |
| [H-04](#h-04) | Missing Maximum Bond Signature Parameter |
| [H-05](#h-05) | Service Owner Can Steal Protocol Tokens by Exploiting Reentrancy in `create()` |
| [H-06](#h-06) | Token Callback Reentrancy |
| [H-08](#h-08) | Balancer Oracle Uses Vault Balances as Price and Can Be Steered by Anyone |
| [H-09](#h-09) | Critical Logic Inversion in Price Guard Allows Flash-Loan Manipulation of Liquidity Operations |
| [H-10](#h-10) | Balancer Oracle Update Can Mutate State Even When It Returns False |
| [H-11](#h-11) | Broken TWAP Validation Allows Spot-Price Manipulation and Renders Slippage Checks Ineffective |
| [H-12](#h-12) | Missing Deadline Parameter in Register Signatures |

#### Medium

| ID | Title |
|----|-------|
| [M-01](#m-01) | Uniswap Oracle `validatePrice` Can Be Griefed Per Block via `sync()` |
| [M-02](#m-02) | `changeRanges` Silently Fails When Price Is Out of Tick Range |
| [M-04](#m-04) | `checkpoint()` Does Not Correct `effectiveBond` Downward at Year Boundaries Where Inflation Decreases |
| [M-05](#m-05) | Services Can Earn Undeserved Rewards by Manipulating Checkpoint Timing During Reward Droughts |
| [M-06](#m-06) | `BalancerPriceOracle::validatePrice` Uses Stale TWAP |
| [M-07](#m-07) | Incorrect Proportional Reward Splits When an Operator Has Been Slashed |
| [M-08](#m-08) | Arbitrum Retryable-Ticket Refund/Value Not Verified Enables Timelock ETH Exfiltration |
| [M-09](#m-09) | Malicious User Can Prevent Buying Back OLAS Token via Slipstream by Transferring Token to Slipstream Router |
| [M-12](#m-12) | DoS in Liquidity Migration Due to Unit Mismatch in `UniswapPriceOracle` |

---

## My Findings

---

## <a id="m-11"></a>M-11: Price Cumulative Last Is Used Inverted in Uniswap Oracle

1. The price oracle retrieves the token price from Uniswap pool based on swap direction.
2. The price call is inverted. When `direction = 0`, it should call `price0cumulativeLast()`.

```solidity
// @note both prices were swapped
if (direction == 0) {
    cumulativePriceLast = IUniswapV2(pair).price1CumulativeLast();
} else {
    cumulativePriceLast = IUniswapV2(pair).price0CumulativeLast();
}
```

### Assumption

1. Dev didn't consider what the function fetches, and inverted both of the query.
2. A simple test would catch this, but no test was implemented.

### Heuristic

1. Ensure price fetching is always correct.

---

## Findings I Missed

---

## High

## <a id="h-01"></a>H-01: Variable Overwrite Makes Deviation Check Useless

### Summary

1. `centerSqrtPriceX96` first was retrieved from Pool Slot0.

```rust
(
    centerSqrtPriceX96,
    observationIndex
) = _getPriceAndObservationIndexFromSlot0(pool);
```

1. However it is overwritten when retrieving from Uniswap TWAPOracle. Hence the twapPrice and centerSqrtPriceX96 are the same variable.
2. Therefore using them as deviation will always result in 0 deviation, which means 0 protections at all.

```rust
(twapPrice, centerSqrtPriceX96) = abi.decode(
    returnData,
    (uint256, uint160)
);
```

### Takeaway

### Assumptions

1. Dev assumed the price they compare are correct.
2. This is a classic mistake

### How do I spot this

1. Whether a value gets overwritten, check properly what it is being assigned to.
2. Trace any comparison properly to ensure they are being compared correctly.

---

## <a id="h-02"></a>H-02: Incorrect TWAP Calculation in `BalancerPriceOracle` Allows Price Manipulation

Two issues in BalancerPriceOracle implementation

1. Accumulating `averagePrice` instead of `lastPrice`, so the `accumulatePrice` will deviate a lot overtime due to recursive averaging effect.

- Correct formula => `averagePrice = lastPrice * elapsedTime`

```javascript
snapshot.cumulativePrice += snapshot.averagePrice * elapsedTime;
```

1. Incorrect average calculation:

- Correct formulat => `average = cumulativePrice / totalTime`
- But it uses `cumulativePrice / averagePrice` to retrieve the `totalElapsedTime`. Further increase the inaccuracy due to truncation

```javascript
uint256 averagePrice = (snapshot.cumulativePrice +
    (currentPrice * elapsedTime)) /
    ((snapshot.cumulativePrice / snapshot.averagePrice) + elapsedTime);
```

`cumulativePrice = Σ (price_i × elapsed_i)`

### Takeaway

### Assumptions

1. Dev assumed it is safe to reverse-engineer `totalElapsedTime`, however when there are truncation involved, the accuracy will be bad.
2. Wrong understanding of how `averagePrice` works. AveragePrice is the accumulation of all lastPrice over their respective timeElapsed.

### How to spot this

1. Always ensure Price calculation is correct. Understand the exact formula in TWAP calculation.

---

## <a id="h-03"></a>H-03: Insolvency via Cross-Service Reentrancy in StakingBase._withdraw

1. The `unstake()` => `_withdraw` function in `StakingBase.sol` violates the Checks-Effects-Interactions (CEI) pattern, allows for reentrancy
2. The function did delete the `serviceId` claimed, but an owner can use a different service ID to reenter back into the contract.
3. The impact is balance only being updated once, but the attacker can withdraw multiple times. Therefore the Staking Contract is insolvent

### Takeaway

### Assumptions

1. Dev thought that they already deleted the ServiceId struct
2. But didn't consider that same Owner can re-enter via a different serviceId

### How to spot this

1. Whenever there's a state update with ETH, must follow CEI.
2. If not follow CEI, then immediately explore any reentrancy issue.

---

## <a id="h-04"></a>H-04: Missing Maximum Bond Signature Parameter

### Summary

1. Operator can sign an off-chain `signature` to engage with a service owner at a certain bonded ETH
2. The service owner will then `activateRegistration` on behalf of the operator onchain with that bonded ETH amount
3. However, the signature doesn't include the bond ETH, so service owner can terminate the current service, increase the bond ETH and re-use the operator's previous signature, forces the operator to bond more.

### Takeaway

1. Dev assumes `The signature proves the operator consented to register these specific agents for this specific service. The nonce prevents replay.`, but missed out the detail that this signature were supposed for.

### How to spot this

1. Next time ask:

- What's in the hash? List every parameter the signer commits to
- What does the on-chain execution actually enforce
- Is there a gap between?

---

## <a id="h-05"></a>H-05: Service Owner Can Steal Protocol Tokens by Exploiting Reentrancy in `create()`

### Summary

1. `ServiceManager.create()` does not follow CEI pattern. It calls `ServiceRegistry.create()`(which uses `_safeMint`) before `ServiceRegistryTokenUtility.createWithToken()`(sealing the token)
2. This allows service creator to reenter contract during `onERC721Received` callback.

### Attack description

1. Service owner calls create and bond with 100 usd.
2. The `create()` mints NFT to the service owner first before `createWithToken`(confirming the deal)
3. ServiceOwner can reenter with `onERC721Received` and call `update` with lower bond ie. 1 WEI, then `activateRegistration` with 1 wei and `registerAgents`. Operator bond recorded as 1 wei.
4. Execution context returned to `_safeMint`
5. Lastly `createWithToken` using 100usdc. So the protocol assumed Service Owner owns 100usdc.
6. Service owner can withdraw 100usdc after terminate

```rust
ServiceManager.create(serviceOwner=attacker, token=USDC, bond=100 USDC)
│
├─ Line 199-213: Copy bonds[i] = 100 USDC, set agentParams[i].bond = 1 wei
│
├─ Line 216: ServiceRegistry.create(bond=1 wei)
│   ├─ Records service with bond = 1 wei in ServiceRegistry
│   ├─ State = PreRegistration
│   └─ _safeMint(attacker, serviceId)  ← NFT sent to attacker
│       │
│       └─ onERC721Received() CALLBACK → attacker has control
│           │
│           │  At this moment:
│           │  - Attacker owns the service NFT ✓
│           │  - Service state = PreRegistration ✓
│           │  - ServiceRegistry bond = 1 wei
│           │  - ServiceRegistryTokenUtility bond = NOT SET YET
│           │
│           ├─ Step A: attacker calls ServiceManager.update(token=ETH, bond=1 wei)
│           │   ├─ token == ETH_TOKEN_ADDRESS path (line 255)
│           │   ├─ ServiceRegistry.update(bond=1 wei) ← keeps bond tiny
│           │   └─ resetServiceToken(serviceId) ← clears any token record
│           │       (nothing to clear since createWithToken hasn't run yet)
│           │
│           ├─ Step B: attacker calls ServiceManager.activateRegistration()
│           │   └─ Pays security deposit of 1 wei
│           │   └─ State = ActiveRegistration
│           │
│           ├─ Step C: attacker calls ServiceManager.registerAgents{value: 1 wei}()
│           │   └─ ServiceRegistry checks: msg.value == agentParams.bond (1 wei) ✓
│           │   └─ Operator bond recorded as 1 wei
│           │   └─ State = FinishedRegistration
│           │
│           └─ returns to _safeMint
│
├─ Line 224: ServiceRegistryTokenUtility.createWithToken(
│       serviceId, USDC, agentIds, bonds=[100 USDC])
│   │
│   │  This uses the ORIGINAL bonds array from line 209!
│   │  The attacker's update() call didn't change this local variable.
│   │
│   └─ Records: mapServiceAndAgentIdAgentBond = 100 USDC
│   └─ Records: mapServiceIdTokenDeposit = {token: USDC, deposit: 100 USDC}
│
└─ create() returns
```

### Takeaway

### Assumption

1. Dev assumed that `ServiceRegistry::create()` has reentrancy, so it must be safe.
2. Likely looking at `ServiceRegistry` in isolation, not in the whole system.

### How to spot this

1. Think of cross-contract reentrancy, be alert when there isn't a global reentrancy guard.
2. Ask: What state is NOT yet written when an external call happens.

---

## <a id="h-06"></a>H-06: Token Callback Reentrancy

### Summary

Similar to H-03

## <a id="h-08"></a>H-08: Balancer Oracle Uses Vault Balances as Price and Can Be Steered by Anyone

### Summary

1. BalancerOracle uses vault balance as Price and can be steered by anyone

```javascript
function getPrice() public view returns (uint256) {
    (, uint256[] memory balances, ) = IVault(balancerVault).getPoolTokens(
        balancerPoolId
    );
    // Native token
    uint256 balanceIn = balances[direction];
    // OLAS
    uint256 balanceOut = balances[(direction + 1) % 2];

    // @audit Directly uses price, not TWAP, can be manipulated by flashloan
    return (balanceOut * 1e18) / balanceIn;
}
```

### Takeaway

### Assumption

1. Dev assumed this gets the correct price. But the pool reserve can be manipulated easily with flashloan

### How to spot this

1. Beware of any Oracle which doesn't use TWAP.

## <a id="h-09"></a>H-09: Critical Logic Inversion in Price Guard Allows Flash-Loan Manipulation of Liquidity Operations

### Summary

1. The early return check is FLAWED. It returns when the pool doesn't have long enough history.
2. But it should return the centered price when pool HAS enough history.
3. Further it also return centered price when TWAPOracle call failed.
4. It means this entire function has no protection at all.

```javascript
// @audit this check is reversed, instead of IF the pool has long enough history, use that price
// @audit this becomes if pool doesn't have enough history, use less history price
if (oldestTimestamp + SECONDS_AGO < block.timestamp) {
    return centerSqrtPriceX96; // <@-- @audit
}
```

### Takeaway

### Assumptions

1. Dev assumes returning early instead of blocking transaction is safe

### How to spot this

1. Ensure TWAP price is returned all the time, remember SPOT price is easily manipulatable.

---

## <a id="h-10"></a>H-10: Balancer Oracle Update Can Mutate State Even When It Returns False

### Summary

1. `BalancerOracle` doesn't REVERT, only return FALSE, but previous state changes already committed.
2. This creates a double counting issue.

```javascript
// This implementation only accounts for the first price update in a block.
// Calculate elapsed time since the last update
uint256 elapsedTime = block.timestamp - snapshot.lastUpdated;

// Update cumulative price with the previous average over the elapsed time
snapshot.cumulativePrice += snapshot.averagePrice * elapsedTime;

// Update the average price to reflect the current price
uint256 averagePrice = (snapshot.cumulativePrice +
    (currentPrice * elapsedTime)) /
    ((snapshot.cumulativePrice / snapshot.averagePrice) + elapsedTime);

// Check if price deviation is too high
if (
    currentPrice <
    averagePrice - ((averagePrice * maxSlippage) / 100) ||
    currentPrice > averagePrice + ((averagePrice * maxSlippage) / 100)
) {
    return false; // <@-- @audit doesn't REVERT here, but state already changed
}
```

### Takeaway

### Assumptions

1. Dev assumes the outer function can handle when the Oracle return FALSE

### How to spot this

1. Change for any state changes before function returns. For any failure that supposed to REVERT but didn't.

## <a id="h-11"></a>H-11: Broken TWAP Validation Allows Spot-Price Manipulation and Renders Slippage Checks Ineffective

1. `UniswapPriceOracle` tautology, `deviation = |spotPrice - spotPrice| = 0`, hence always using the spot price.

### Fix

```javascript
// Actual formula
timeWeightedAverage = (cumulativeNow - cumulativePast) / (timestampNow - timestampPast)

// Store a snapshot at time T1
uint256 savedCumulative = pair.price0CumulativeLast();
uint256 savedTimestamp = block.timestamp;

// Later, at time T2, compute TWAP
uint256 currentCumulative = pair.price0CumulativeLast();
uint256 twap = (currentCumulative - savedCumulative) / (block.timestamp - savedTimestamp);
```

### Takeaway

### Assumptions

1. Dev assumes the calculation is correct, they did not store previous price and timestamp.

### How to spot this

1. TWAP is calculated as

```javascript
TWAP = (new_price - oldPrice) / (currentTime - oldPriceTime)
```

Pay attention to any deviation from this formula

## <a id="h-12"></a>H-12: Missing Deadline Parameter in Register Signatures

### Summary

1. `registerAgentsWithSignature` function allows a service owner to register agent on behalf of an operator.
2. This allows the service owner the approval to use the operator's signature indefinitely.
3. Even if the operator wants to unbond, the service owner can forcibly transfer operator's token.

### Takeaway

### Assumptions

1. Dev just want to ensure the operator can sign.
2. But it failed to ensure what the operator is signing for.

### How to spot this

1. Whenever there's an signature, IMPORTANT to ensure what the signer is signing for.

## MEDIUM

## <a id="m-01"></a>M-01: Uniswap Oracle validatePrice Can Be Griefed Per Block via sync()

### Summary

1. `validatePrice` in Uniswap V2 checks `blockTimestampLast` equals current `block.timestamp`. Because Uniswap V2 pairs has a permissionless `sync()` function which updates the `blockTimestampLast = block.timestamp`
2. Attacker can front-run any victim transaction in the same block. Or even worse if anyone call `sync` before.

```javascript
blockTimestampLast = uint32(block.timestamp);
```

### Takeaway

### Assumptions

1. Dev didn't consider the `sync()` function in uniswap, it is callable by anyone to update, causing this revert.

### How to spot this

1. Understand uniswap V2 has this [`sync()`](https://github.com/Jeiwan/zuniswapv2/blob/50fb69e95805970e9f0f118fc797b0a02f74f43e/src/ZuniswapV2Pair.sol#L179) feature, which can be used to update price and the timestamp.

## <a id="m-02"></a>M-02: changeRanges Silently Fails When Price Is Out of Tick Range

### Summary

1. `LiquidityManager::changeRanges` decreaseLiquidity and only handles when both tokens being returned(Tick in range)
2. For position that is not in range when either token0 or token1 == 0, there is no failure check.

### Takeeway

### Assumptions

1. Dev didn't handle the situation when the tick is out of range.

### How to spot this

1. Consider that every path is handled properly. What has changed in a path, and what hasn't been changed.

## <a id="m-04"></a>M-04: checkpoint() Does Not Correct effectiveBond Downward at Year Boundaries Where Inflation Decreases

### Summary

1. Context

- `maxBond` - scheduled/predicted bond allocation
- `effectiveBond` - actual running balance of bond available.

1. When crossing from high rate => low rate. In the effective bond calculation, the function did not remove the balance from effective balance when maxBond > effectiveBond
2. By right the extra emission should have been removed.

```rust
// @note adjust inflationPerEpoch
inflationPerEpoch = curInflationPerSecond * diffNumSeconds
```

### Takeaway

### Assumptions

1. Dev didn't handle all conditions well.

### How to spot this

1. For any function with only `if` condition, ask what happens when ELSE is true, is it okay to ignore.

## <a id="m-05"></a>M-05: Services Can Earn Undeserved Rewards by Manipulating Checkpoint Timing During Reward Droughts

1. Context- service owner activities tracking, via service Info nonce increases.
2. the reward eligible check is `activity / timeElapsed`.
3. In the `_calculateStakingRewards()` function, the serviceCheckpoint is only updated when there are reward to distribute. So essentially the timeElapsed becomes stale, allowing service owner to claim over a larger time period.
4. This creates an issue where the service owner can remain inactive, and only becomes active when there are rewards to distribute, allowing the service owner to claim reward retroactively.

```solidity
if (
    size > 0 && block.timestamp - tsCheckpointLast >= livenessPeriod && lastAvailableRewards > 0 // @note If no reward, timestamp is not updated.
) {
    if (ts > serviceCheckpoint) serviceCheckpoint = ts;
}
```

### Assumptions

1. Dev's intention to bypass the checkpoint if there isn't reward. They missed that in the scenario there will be a misalignment between nonce activity and global reward claim timestamp.

### How to spot this

1. Understand global reward tracking timestamp must get updated continuously. If there is stale timestamp, other user can claim reward retroactively.
2. This is a much complex bug, spotting it requires understanding of how eligible ratio is checked. `Activity / ts`, if the ts is stale(large), it allows user o artificially jack up the value, which doesn't encourage consistent engagement.

## <a id="m-06"></a>M-06: BalancerPriceOracle::validatePrice Uses Stale TWAP

1. BalancerPriceOracle contract has `PriceSnapshot public snapshotHistory`, which stores the latest price.
2. `validatePrice()` computes a **TWAP** using stored snapshot values without first ensuring the snapshot is current.
3. Therefore the TWAP calculation can be wrong.

### Assumption

1. Dev thought storing current price in the contract is a good architecture
2. `validatePrice()` didn't call `updatePrice` before validate the price. Cause price to be inaccurate due to stale price

### How to spot this

1. Ensure latest price is called before any validation or before using in any area, unless specifically for past prices.

## <a id="m-07"></a>M-07: Incorrect proportional reward splits when an operator has been slashed

1. `StakingBase` contract allows service owners to select a reward distribution type when allocation rewards.
2. For proportional distribution, the service owner who go`t slashed still receive equal shares of staking reward.
3. This distribution is unfair and the protocol can't differentiate between honest operator and operator who got slashed

```solidity
enum RewardDistributionType {
    // Rewards are divided as per where stake comes from, proportional
    Proportional, // <@--- proportional among service owner and operator
    // Rewards go to service owner
    ServiceOwner,
    // Rewards go to service multisig
    ServiceMultisig,
    // Custom rewards distribution
    Custom
}
```

### Assumptions

1. Dev didn't consider the slashing and staking. They didn't focus on the correcting the staking reward distribution after handling the slashing.

### How to spot this

1. Whenever there are punitive actions, check what does it affect. Slashing/Banning/Blacklisting
2. For any staking reward, check if there are any actions that could affect it. Any missing action is a bug

## <a id="m-08">Arbitrum Retryable-ticket refund/value not verified enables Timelock ETH exfiltration

A. Understanding Gnosis Safe wallet flow

1. Safe -> GuardCM(Guard implementation) -> If passes -> Calls Timelock contract
2. `GuardCM._verifySchedule` function didn't check the ETH value.
3. This creates an attack path(only if the Safe wallet is compromised and only affecting Arbitrum):
a. Attacker passed some ETH value in the param
b. Attacker can set their address as the recipient for Arbitrum retry ticket refund.

```solidity
(targets[0],, callDatas[0],,,) = abi.decode(
    payload,
    (
        address,
        uint256, // <@-- @audit ETH value, not checked
        bytes,
        bytes32,
        bytes32,
        uint256
    ));
```

**Fix:**

1. Enforce ETH = 0
2. Check refund recipient address from Arbitrum's retry

### Assumption

1. Dev assumed validating address, chainId are sufficient. Didn't validate ETH value passed in.
2. Didn't cover Arbitrum's refund process. Arbitrum refunds excess gas ETH value to recipient address.

### How to spot this

1. Check if all the data is validated. Address, chainId, value, etc..
2. Understand how bridges validate their calldata

## <a id="m-09"></a>M-09: Malicious user can prevent buying back OLAS token via Slipstream by transferring token to Slipstream Router

1. Whenever protocol buying back OLAS via Slipstream V3, the swap router's `refundETH()` function refunds any extra ETH to the `msg.sender`.
2. Issue arise when the `BuyBack` contract doesn't have `receive()` function.
3. Attacker can transfer small amount of ETH to router, triggering refundETH, and the BuyBack process will fail due to missing `receive()` function.

### Assumption

1. Dev didn't consider this attack path, not having receive function in the BuyBack contract

### Heuristic

1. Whenever any flow involves refund native ETH, check whether the contract has a `receive` function
2. Checklist:

```
1. Is the external function payable?         → ETH might flow through
2. Does the external protocol refund ETH?    → check their router/contract source
3. Who is msg.sender in that external call?  → that's who receives the refund
4. Does that msg.sender have receive()?      → if not, revert risk
5. Is there a sweep/rescue function?         → if not, stuck ETH risk
```

## <a id="m-12"></a>M-12: DoS in Liquidity Migration Due to Unit Mismatch in UniswapPriceOracle

1. A mismatch between price derivation which uses `1e16` but the slippage parameter provided in raw percentage units(`50` for 50%).
2. In the

```solidity
// @note in LiquidityManagerETH, when passing in slippage
if (!IOracle(oracleV2).validatePrice(maxSlippage / 100)) // <@--- raw percentage unit passed in
{
    revert SlippageLimitBreached();
}

// @note in UniswapPriceOracle, unit in 1e16, not 100% points
uint256 derivation = (tradePrice > timeWeightedAverage)
    ? ((tradePrice - timeWeightedAverage) * 1e16) / timeWeightedAverage
    : ((timeWeightedAverage - tradePrice) * 1e16) / timeWeightedAverage;
```

### Assumption

1. Dev assumed everything operate in the correct decimals

### Heuristic

1. Ensuring all the calculation operates in the same decimals.
