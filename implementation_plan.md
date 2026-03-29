# Cross-Draft Evidence Architecture Changes

**Date:** 2026-03-29T07:56:00-07:00 (US Pacific)

This plan consolidates the design decisions from our discussion into concrete changes for both the Actor Chain and Intent Chain drafts.

## Proposed Changes

### Intent Chain Draft

#### [MODIFY] [draft-mw-spice-intent-chain.md](file:///home/mw/ietf-rfc8693-intent-chain/draft-mw-spice-intent-chain.md)

---

**Change 1: Replace Merkle Tree with Hash Chain**

| Aspect | Detail |
|:---|:---|
| **What** | Replace `intent_root` (Merkle tree root) with `intent_hash` (sequential hash chain) |
| **Benefit** | Aligns with Actor Chain's `actc` cumulative commitment pattern; simpler to implement; eliminates proof generation/verification complexity; O(n) forensic verification is acceptable for audit-plane (5–50 entries) |

Specifically:
- Replace the `intent_root` claim with `intent_hash` — a running chain hash
- Remove `intent_alg` claim (unnecessary with hash chain)
- Remove Appendix A (Merkle tree construction + reference algorithm, lines ~1124–1167)
- Replace the "Design Rationale: Merkle Root in Token" section (lines 139–150) with hash chain rationale
- Simplify forensic verification (Section 5.2, lines 669–677): recompute sequential chain hash instead of Merkle root
- Update IANA section: register `intent_hash` instead of `intent_root`, remove `intent_alg`
- Update all token examples to use `intent_hash` instead of `intent_root`

---

**Change 2: Add `input_hash`/`output_hash` to `act` Claims**

| Aspect | Detail |
|:---|:---|
| **What** | Define two OPTIONAL extension claims within each `act` object: `input_hash` and `output_hash` |
| **Benefit** | Cross-AS content linkage verification without shared registry access; self-contained evidence in multi-AS deployments; O(1) data-plane structural check |

Specifically:
- Add new section: "Intent Evidence in Actor Chain Claims" defining the two fields
- Add verification rule: `act[i].output_hash == act[i+1].input_hash`
- Clarify the one-to-many collapse: `act` hashes are segment boundaries; registry entries are segment internals
- Update combined token format example (lines 556–581) to show inline hashes
- Add three-tier evidence model table (structural → commitment → forensic)

---

**Change 3: Strengthen Multi-AS Deployments Section**

| Aspect | Detail |
|:---|:---|
| **What** | Reframe Multi-AS (lines 813–822) as the primary enterprise deployment pattern, not an edge case |
| **Benefit** | Justifies the protocol-level machinery to IETF reviewers; positions inline evidence as a federation-enabling feature |

Specifically:
- Add examples of why multiple ASes exist (M&A, business unit autonomy, multi-cloud, regulatory segmentation)
- Add "Federated TTP Chain" pattern: each AS acts as a local Trusted Third Party
- Explain that inline `input_hash`/`output_hash` enable cross-boundary verification without shared registry

---

**Change 4: Formalize Evidence Composability**

| Aspect | Detail |
|:---|:---|
| **What** | Add section explicitly naming the "Evidence Composition via Policy Evaluation" pattern |
| **Benefit** | Clarifies that chains are evidence suppliers (not weight suppliers); policy engine is the composition operator; chains are independently evaluable |

Specifically:
- State that Intent Chain supplies evidence (facts), not weights (decisions)
- Define `Decision = Policy(ActorEvidence ∪ IntentEvidence ∪ InferenceEvidence)`
- Clarify no chain embeds another chain's evidence format — only correlation identifiers (`acti`, `sub`, `iat`) and commitment hashes cross boundaries

---

**Change 5: Clarify Verification Benefits of Hash-Only Evidence**

| Aspect | Detail |
|:---|:---|
| **What** | Add explicit section on what hash-only evidence proves vs. what requires content |
| **Benefit** | Sets honest expectations; positions the intent chain as "tamper-evident process audit" with deterrence value |

Specifically:
- Verifiable without content: chain integrity, non-repudiation of participation, ordering, completeness, filter presence
- Requires content (produced on demand during disputes): substantive proof of what was said
- Analogy: sealed evidence chain-of-custody / financial audit trail

---

### Actor Chain Draft

#### [MODIFY] [draft-mw-spice-actor-chain.md](file:///home/mw/ietf-rfc8693-actor-chain/draft-mw-spice-actor-chain.md)

---

**Change 6: Add Multi-AS Motivation**

| Aspect | Detail |
|:---|:---|
| **What** | Add paragraph to Introduction/Architecture explaining that multi-AS is common in large enterprise |
| **Benefit** | Justifies why the nested `act` structure and cross-domain re-issuance matter; helps IETF reviewers understand the real deployment landscape |

Specifically:
- Add to the "Same-Domain and Cross-Domain Hops" section (lines 434–449) or a new companion subsection
- Enumerate patterns: M&A, business unit autonomy, multi-cloud, regulatory segmentation
- State that the nested `act` ensures delegation evidence is self-contained across AS boundaries

> [!IMPORTANT]
> Changes to the Actor Chain draft are minimal — one motivational paragraph. The Intent Chain draft carries all the normative changes. This preserves the Actor Chain's existing extensibility: `act` is already defined as an extensible object, so the Intent Chain can add `input_hash`/`output_hash` without modifying Actor Chain normative text.

---

## Summary Table

| # | Change | Draft | Benefit |
|:---|:---|:---|:---|
| 1 | Merkle → hash chain | Intent | Simplicity, alignment with `actc`, same verification pattern |
| 2 | `input_hash`/`output_hash` in `act` | Intent | Cross-AS content linkage, O(1) data-plane check |
| 3 | Multi-AS as primary pattern | Intent | IETF justification, federation framing |
| 4 | Evidence composability | Intent | Clean separation: evidence ≠ weights |
| 5 | Hash-only verification benefits | Intent | Honest framing, deterrence model |
| 6 | Multi-AS motivation | Actor | Real-world deployment justification |

## Verification Plan

These are IETF Internet-Draft specification documents (not code), so verification is editorial review:

### Manual Verification
1. **Consistency check**: After changes, grep for `intent_root`, `intent_alg`, and `Merkle` to ensure no stale references remain in the intent chain draft
2. **Token example validity**: Verify all JSON token examples use `intent_hash` (not `intent_root`) and that examples with `act` claims include `input_hash`/`output_hash`
3. **Cross-reference check**: Verify that the Actor Chain draft's references to the Intent Chain (`I-D.draft-mw-spice-intent-chain`) still make sense after changes
4. **Hash chain consistency**: Verify the hash chain construction description is consistent with the `actc` pattern in the Actor Chain draft
5. **IANA section**: Verify claim registrations are updated (`intent_hash` replaces `intent_root`, `intent_alg` removed)
