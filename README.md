# Artifact: which object does a pre-signature defense inspect?

Anonymized artifact for a double-blind submission. Title, authors, affiliation
and archival identifiers are withheld until notification.

A defense that runs before a signature is asked about one artifact: the
transaction or typed message the signer is about to authorize. This harness
measures, at four sites, whether that artifact is the one that determines the
outcome. Three sites concern wallet defenses; the fourth concerns intent
settlement, where the user signs an order and a solver authors the transactions
that fill it.

Nothing here is an attack. The measurement is about defense input selection: the
address whose code a checker reads, the field a policy evaluates, the
transaction a corpus labels, and the contract set a solver chooses after the
signature.

## Requirements

[Foundry](https://getfoundry.sh) (`anvil`, `cast`, `forge`) and `python3`. No
`pip` or `npm` is needed for the core; the harness shells out to `cast`.

Put optional API keys in a gitignored `.env` next to this file:

| key | enables |
|---|---|
| `ETHERSCAN_API_KEY` | verified-source lookups (§4) and settlement fetching (§5). Free tier is enough: 5 calls/sec, 100k/day. Use of the API requires the "Powered by Etherscan.io APIs" attribution shown below. |
| `ALCHEMY_ENDPOINT_URL` or `MAINNET_RPC` | an **archive** RPC, required for §4. Code presence is queried at each row's signing block; a non-archive endpoint cannot answer that and the harness records the row as `unknown` rather than guessing. |
| `GO_PLUS_APP_KEY` + `GO_PLUS_APP_SECRET` | the live address-reputation lens |
| `ANTHROPIC_API_KEY` (plus `pip install anthropic`) and/or `LAKERA_GUARD_API_KEY` | makes the plan-review rung call a real model or guardrail instead of modelling one |

Unconfigured defenses are skipped, never faked.

## Which command produces which section

| paper section | command | needs |
|---|---|---|
| §2 corpus reconstruction | `python3 -m demo.reconstruct` | `ETHERSCAN_API_KEY` |
| §3 eight-drain capability ladder | `./run.sh` | Foundry only |
| §4 source availability on the authority object | `./run-measure.sh` | `ETHERSCAN_API_KEY` + archive RPC |
| §4 per-row record behind those counts | `python3 -m demo.source_tier` | nothing (shipped cache) |
| §4 upgrade-class test (target vs authority object) | `python3 -m demo.upgrade_tier` | GoPlus keys |
| §5 signed order vs executed contracts | `python3 -m demo.intent_gap ... --end-block 25660951` | `ETHERSCAN_API_KEY` |
| §5 what those contracts are | `python3 -m demo.intent_contracts` | `ETHERSCAN_API_KEY` |
| §5 anchor sensitivity | `python3 -m demo.intent_gap ... --anchor-sweep 9 --anchor-step 100` | `ETHERSCAN_API_KEY` |

Shipped outputs from the runs the paper reports are in `results/`, so every
per-row number can be checked without an API key or a re-run.

## §2: the corpus

`corpus/real/ptxphish_sample.json` carries 140 victim-signed rows: 101 malicious
and 39 benign controls, in six classes. The malicious rows are the transactions
the victims signed, not the sweeps that consumed them; for the approval classes
the grant is recovered from `Approval` / `ApprovalForAll` logs, because the
labelled incident points at the attacker's later sweep.

Two sampling limits that bound every count downstream:

- The rows are the **head of each class column** in the source spreadsheet, not
  a random draw. Reconstruction ran until each class reached twenty rows and two
  classes fell short, so 101 is a sampling decision, not a population.
- The 39 benign controls are ordinary mainnet activity from 2017-2021 and are
  **not class-matched**: they contain no `upgradeTo` and no bulk transfers, so
  they cannot support a false-positive rate for those classes.

## §3: the capability ladder

```bash
./run.sh
```

Boots a local `anvil` on the Prague hardfork, deploys a mock USDC, and scores
eight hand-built drains against a monotone ladder of seven defense capabilities:
plan review, address allowlist, amount-aware clear-signing, recipient rendering,
transaction simulation, signature simulation, and a categorical transaction-type
policy. Each drain is scored at the lowest rung that stops it. Writes
`out/scorecard.{json,md}`.

The suite was built to separate the capabilities it is scored against, so its
counts are structural and carry no rate. Two of the eight (D and F) are the
shape the paper is about: the allowlist reads a genuinely trusted counterparty
while the authority sits in another field of the same signed object. The rest
fail for other reasons, which `out/scorecard.md` states per row.

## §4: source availability on the authority object

*Powered by [Etherscan.io](https://etherscan.io) APIs.*

Every other tier inspects the transaction. A code-reading tier has to resolve a
prior input: the address whose code governs the outcome. For most drain shapes
that is not the transaction target.

```bash
./run-measure.sh          # or: python3 -m demo.measure
```

`demo/source_tier.py` resolves the authority object per class (the spender for
an approval, the recipient for a helper transfer, the `upgradeTo` argument for
a proxy upgrade, the target itself for an opaque call), then reports what a code
reader would have. States are **availability, not detection**:

- `catch` — verified source exists for the governing object
- `blind` — code, but no verified source: bytecode only
- `na` — no code at all at the signing block
- `unknown` — the lookup could not be made (archive call failed, or the call cap
  was hit). Excluded from every rate. Folding it into `na` would let a run
  without an archive endpoint report "no code at all" for every row.

The tier deliberately does not judge whether the code it finds is malicious.

Measured over the 100-row analysis set (the 101 malicious rows less `ptx-J-01`,
which is probably mislabelled; see below):

```
class                rows  the tx `to`                     authority object     catch blind  na
approve/forAll         21  12 verified tokens              the spender (15)         0     0  21
transfer via helper    20  1 Seaport helper                the recipient (4)        0     0  20
upgradeTo              19  19 victim-owned proxies         the implementation (5)  16     3   0
opaque call            40  10 attacker contracts           the target itself (10)  36     4   0
                      ---                                                         --- ----- ---
total                 100                                                          52     7  41

tx target verified but NOT the authority object: 60 / 100
unknown: 0  (every row resolved against the archive RPC)
```

Per-row output, including each authority object, its signing block, the raw
`eth_getCode` result and the source status, is in
`results/source_tier_rows.json`. The 100 rows resolve to only **33 distinct
authority objects** (15 spenders + 4 recipients + 5 implementations + 10 opaque
targets = 34 addresses, less one that is both a spender and a recipient), so
the states are reported as counts, never as rates.

Two rows worth knowing about:

- **`ptx-J-01` is excluded from the analysis set.** Its `upgradeTo` argument is
  the sender's own externally owned account: the signer repointed their own
  proxy at themselves. The corpus inherits it from a heuristic that labels an
  `upgradeTo` a scam when the proxy owner is the sender, which also fires on an
  owner disabling a proxy they no longer trust. Including it gives 42 of 101 and
  a divergence of 61 of 101.
- **`ptx-H-01`'s recipient is an EOA, not a contract.** It held no code at the
  signing block (18,437,490) and returns 23 bytes today: `0xef0100…`, an EIP-7702
  delegation designator. The address is still an externally owned account
  pointing at delegate code. A latest-block check would both credit a
  signing-time reader with code it could not have read and misclassify an EOA as
  a contract. `source_tier.py` detects the designator prefix explicitly rather
  than treating any non-empty `eth_getCode` as a contract.

Code presence is queried at each row's signing block against an archive RPC.
Verification status has no historical equivalent to query, so it is measured as
of now and is an upper bound.

## §4b: does object selection change what a deployed defense says?

Everything above locates an object. It does not test a defense. For approvals
and transfers it does not need to, because deployed wallets already read the
object resolved here. The exception is the proxy-upgrade class, and
`demo/upgrade_tier.py` is the test for it.

The design is within-subjects: one live reputation service (GoPlus), the same
19 transactions, asked twice, varying only which address it is handed.

```bash
python3 -m demo.upgrade_tier                 # the within-subjects test
python3 -m demo.upgrade_tier --benign-scan   # the type-level-rule check
```

```
GoPlus aimed at the transaction target (the proxy):        flagged  0 / 19 rows
GoPlus aimed at the authority object (the implementation): flagged 18 / 19 rows
                                                           (4 of 5 distinct)
```

Two bounds. Reputation is retrospective, so a hit today is not evidence the
service would have fired at signing time; this shows the signal is attached to
an object no tier in this class reads, not that it was available when it would
have helped. And `demo/rabby.py` is deliberately excluded from this test,
because that port does not parse `upgradeTo` at all, so a miss by it would be a
fact about the port rather than about shipped Rabby.

Output: `results/upgrade_tier.json`.

## §5: does the signed order govern which contracts execute?

*Powered by [Etherscan.io](https://etherscan.io) APIs.*

An intent system inverts the signing model: the user signs an order and never
authors the settlement transaction. A solver does, later, and supplies the calls
that run against the user's approved balance.

`demo/intent_gap.py` decodes CoW Protocol `GPv2Settlement.settle` calldata and
asks how many of the contracts that execute appear anywhere in the signed
orders.

```
|T|      distinct interaction targets in the settlement
|S|      addresses derivable from the signed orders (sell token, buy token,
         receiver, and the settlement contract itself)
|T \ S|  contracts that govern execution and are named in no order
```

What the run was expected to show, including its confirmation and falsification
thresholds, was written down before it ran: see [PREDICTION.md](PREDICTION.md).
That file also states plainly what its dates do and do not establish, since the
public copy postdates the measurement. One of its three claims was mis-specified
and is left in place rather than quietly fixed.

Window ends **must** be pinned with `--end-block` for a run to be reproducible.
Without it the harness walks back from the chain tip, so every run samples
different blocks and prints a warning saying so. The reported run is:

```bash
python3 -m demo.intent_gap --windows 7 --per-window 25 --spacing-days 45 \
    --end-block 25660951          # last block before 2026-08-01 15:34 UTC
python3 -m demo.intent_contracts  # classify the contracts named in no order
```

```
settlements            174        7 windows, 2025-11-03 .. 2026-08-01
median |T\S|/|T|       0.750
mean                   0.794 -> 0.777
named none of them     75/174
named all of them       0/174
distinct contracts governing execution but named in no order: 77
  of those: 14 with no published source, 10 proxy-shaped,
            34 deployed under a year before the sample starts
|S| = 4 in 155 of 174 settlements; 3 to 12 in the rest
```

**Most of those numbers are the sampling anchor, not the protocol.** Re-running
the whole design at nine anchors 100 blocks apart, about three hours of chain,
moves the pooled median between 0.708 and 1.000, the named-none count between
75 and 99, and the distinct-contract count between 64 and 83. The one statistic
that survives is the last row above: settlements naming *every* executing
contract number zero in eight of the nine runs and one (of 175) in the ninth.
Reproduce with `--anchor-sweep 9 --anchor-step 100`; the record is in
`results/intent_gap_sensitivity.json`.

Shipped for this section: `results/intent_gap.json` (window block ranges,
per-settlement hashes, decoded `T` and `S`, per-window drop counts),
`results/intent_gap_contracts.{json,md}` (all 77 addresses classified by source
status, proxy status and creation block) and
`results/intent_gap_sensitivity.json` (the anchor sweep).

**This is not a vulnerability claim.** A CoW order's limit price and receiver
are enforced at settlement, so the value outcome is bounded no matter which
contracts execute. That is the design working as intended, and no claim is made
that any solver has exploited any of it. The finding is about what a defense can
*see* at signing time.

Bounds that travel with every number here: `|T|` comes from settlement calldata,
so contracts reached through nested internal calls are invisible, making it a
lower bound that works against the finding rather than for it; each window is a
contiguous run of settlements within a roughly one-day span, so the sample is
seven correlated clusters rather than independent draws; the harness drops any
settlement with an empty decoded interaction set, which is exactly the
population that would falsify the prediction; and `appData`-committed hook
targets are not decoded, so the reported gap is an upper bound.

## What this harness does and does not establish

It **does** produce: a reconstructed corpus of victim-signed drains; a runnable
capability ladder over eight drain shapes; per-row source availability on the
resolved authority object at each row's signing block; and the signed-order
versus executed-contract gap across CoW settlements.

It does **not**: run a code analyser and score its verdicts (the §4 states are
availability, never detection); benchmark any branded wallet product (the ladder
rungs are capability models, with the GoPlus reputation lens the one exception
that queries a live service); or measure false positives on class-matched benign
rows for the upgrade and transfer classes, which the corpus does not contain.

One figure in the paper is **not** regenerated by any command here and came
from a manual pass: the 29-addresses-to-11-bytecodes collapse quoted in the §4
bounds. The §5 sub-population counts (no published source, proxy-shaped,
contract age) used to be manual too and are now computed by
`demo/intent_contracts.py`.

## Layout

```
run.sh                 chain up, eight-drain suite, coverage matrix (§3)
run-measure.sh         the corpus past real deployed defenses (§4)
corpus/real/           the reconstructed victim-signed corpus
results/               shipped outputs of the runs the paper reports
src/MockUSDC.sol       self-contained ERC-20 with EIP-2612 permit
src/Honeypot.sol       allowlisted router that arms after a benign dry-run (drain E)
src/Settlement.sol     allowlisted EIP-712 exchange, recipient set by the order (drain F)
src/AAHelper.sol       allowlisted EIP-7702 delegate that sweeps the account (drain G)
src/Permit2.sol        minimal universal-approval contract, SignatureTransfer (drain H)
demo/cast.py           stdlib wrappers over cast/forge (no web3 dependency)
demo/chain.py          accounts, token, and EIP-2612 / EIP-712 / 7702 / Permit2 signing
demo/attacks.py        the eight-drain suite
demo/reviewers.py      the capability ladder
demo/reconstruct.py    recovers victim-signed grants from Approval logs (§2)
demo/corpus.py         uniform case schema over synthetic and real rows
demo/measure.py        the corpus past real deployed defenses, emits out/measured.json
demo/source_tier.py    source availability on the authority object (§4)
demo/intent_gap.py     signed-order vs executed-contract gap (§5)
demo/rabby.py          port of an open-source wallet's published rule logic
demo/goplus.py         live address-reputation lens
demo/llm.py            optional live plan review
demo/race.py           the drain-E residual: P(drain) = 1 - (1-beta)^K
demo/scorecard.py      runs the suite, emits the coverage matrix
```

## Related work referenced in the code comments

- ERC-7730 clear-signing descriptors: <https://eips.ethereum.org/EIPS/eip-7730>
- PTXPHISH, payload-based transaction phishing on Ethereum: arXiv 2409.02386
- EIP-7702 phishing measured on-chain: arXiv 2512.12174
- "What I Sign Is Not What I See", on human-facing signature legibility: arXiv 2601.16751
- MCP tool poisoning: arXiv 2508.14925
- Agent memory/reasoning-layer injection: arXiv 2503.16248
- Malicious API intermediaries in the agent supply chain: arXiv 2604.08407
