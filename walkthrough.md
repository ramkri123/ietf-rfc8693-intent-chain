# Cross-Draft Evidence Architecture Changes — Walkthrough

**Date:** 2026-03-29T08:48:00-07:00 (US Pacific)

## Changes Made

### Intent Chain Draft ([draft-mw-spice-intent-chain.md](file:///home/mw/ietf-rfc8693-intent-chain/draft-mw-spice-intent-chain.md))

| # | Change | Summary |
|:--|:-------|:--------|
| 1 | **Merkle → Hash Chain** | Replaced `intent_root` with `intent_hash`, removed `intent_alg`, rewrote design rationale, construction algorithm, appendix diagram, forensic verification, IANA registrations (~40 individual replacements) |
| 2 | **Inline `act` Evidence** | Added "Intent Evidence in Actor Chain Claims" section: `input_hash`/`output_hash` OPTIONAL extensions to `act`, cross-hop verification rule, three-tier evidence model table, segment boundary/internal relationship |
| 3 | **Multi-AS Strengthened** | Reframed Multi-AS as primary enterprise pattern (M&A, business unit autonomy, multi-cloud, regulatory segmentation). Added Federated TTP Chain pattern |
| 4 | **Evidence Composability** | Added section formalizing `Decision = Policy(ActorEvidence ∪ IntentEvidence ∪ InferenceEvidence)` and independence/separation/extensibility guarantees |
| 5 | **Hash-Only Verification** | Added section distinguishing what's verifiable without content (chain integrity, non-repudiation, ordering, completeness, filter presence, cross-hop linkage) vs. what requires content (dispute resolution) |

### Actor Chain Draft ([draft-mw-spice-actor-chain.md](file:///home/mw/ietf-rfc8693-actor-chain/draft-mw-spice-actor-chain.md))

| # | Change | Summary |
|:--|:-------|:--------|
| 6 | **Multi-AS Motivation** | Added "Multi-AS Enterprise Reality" subsection explaining real-world deployment patterns and self-contained delegation evidence |

## Verification Results

| Check | Result |
|:------|:-------|
| Stale `intent_root`, `intent_alg`, `Merkle` references | ✅ **Zero** remaining |
| Cross-references (`I-D.draft-mw-spice-intent-chain` in actor chain) | ✅ **5 references intact** |
| `intent_hash` occurrences | ✅ **32** across draft |
| `input_hash`/`output_hash` in `act` claims | ✅ Present in token examples and extension definitions |
| IANA registrations | ✅ Updated (`intent_hash`, `intent_registry`; `intent_alg` removed) |
