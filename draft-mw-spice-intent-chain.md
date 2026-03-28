%%%
title = "Cryptographically Verifiable Intent Chain for AI Agent Content Provenance"
abbrev = "SPICE-INTENT-CHAIN"
category = "info"
docname = "draft-mw-spice-intent-chain-00"
ipr = "trust200902"
area = "Security"
workgroup = "SPICE"
keyword = ["intent chain", "spice", "content provenance", "AI agents", "Merkle tree", "agentic workflows"]
date = 2026-03-28

[seriesInfo]
name = "Internet-Draft"
value = "draft-mw-spice-intent-chain-00"
stream = "IETF"
status = "informational"

[[author]]
initials = "R."
surname = "Krishnan"
fullname = "Ram Krishnan"
organization = "JPMorgan Chase & Co"
  [author.address]
  email = "ramkri123@gmail.com"

[[author]]
initials = "A."
surname = "Prasad"
fullname = "A Prasad"
organization = "Oracle"
  [author.address]
  email = "a.prasad@oracle.com"

[[author]]
initials = "D."
surname = "Lopez"
fullname = "Diego R. Lopez"
organization = "Telefonica"
  [author.address]
  email = "diego.r.lopez@telefonica.com"

[[author]]
initials = "S."
surname = "Addepalli"
fullname = "Srinivasa Addepalli"
organization = "Aryaka"
  [author.address]
  email = "srinivasa.addepalli@aryaka.com"

[normative]
RFC2119 = {}
RFC7515 = {}
RFC7519 = {}
RFC8174 = {}
RFC8693 = {}
RFC8785 = {}

[informative]
RFC6920 = {}
RFC9334 = {}

[informative."I-D.ietf-spice-arch"]
[informative."I-D.draft-mw-spice-actor-chain"]
[informative."I-D.draft-mw-spice-inference-chain"]
%%%

.# Abstract

This document defines the `intent_chain` claim as a companion to the `actor_chain` claim defined in {{!I-D.draft-mw-spice-actor-chain}}. While the actor chain addresses delegation provenance (WHO delegated to whom), the intent chain addresses content provenance (WHAT was produced and HOW it was transformed).

In AI agent workflows, content flows through multiple processing stages including AI agents and filters. The intent chain provides a cryptographically verifiable, tamper-evident record of this content journey. The full intent chain is stored as ordered logs, with only the Merkle root included in the OAuth token for efficiency.

Together, the actor chain and intent chain provide complete governance for autonomous AI agent systems, addressing Spoofing, Tampering, Repudiation, and Elevation of Privilege threats in the STRIDE threat model.

{mainmatter}

# Introduction

## The Problem: Content Provenance Gap

The Actor Chain extension to {{!RFC8693}} (defined in {{!I-D.draft-mw-spice-actor-chain}}) addresses the Delegation Auditability Gap by providing cryptographic proof of the actual delegation path between AI agents. However, it does not address a complementary gap: **Content Provenance**.

In AI agent workflows, content flows through multiple processing stages:

```
Agent A -> Filter -> Filter -> Agent B -> Filter -> Agent C -> Tool
```

Each stage may transform the content. AI agent outputs are inherently non-deterministic and cannot be trusted without validation. Filters (both AI-based and rule-based) transform this content before it reaches the next stage.

For complete governance, systems require proof of:

- **What** each AI agent originally produced (raw output)
- **How** each filter transformed the content
- **Whether** transformations were deterministic (reproducible) or non-deterministic (AI-based)
- **The complete chain** of content transformations within a workflow instance

Without this proof, the content transformation history cannot be reconstructed for audit or dispute resolution. Consider the following repudiation scenario:

1. Agent A produces a response containing a harmful instruction (e.g., caused by prompt injection).
2. The response passes through an AI guardrail filter, which fails to catch the harmful content.
3. Agent B acts on the harmful instruction, causing damage.
4. During investigation, Agent A's operator claims "Agent A never produced that output — it must have been injected by a downstream filter."

Without cryptographic proof binding Agent A's identity to its specific output hash, this claim cannot be disproven. The intent chain solves this by requiring every agent to sign `input_hash` + `output_hash` via `intent_sig`, creating non-repudiable evidence of what each agent received and produced.

## Relationship to Actor Chain and Inference Chain

This specification is part of a three-axis "Truth Stack" for AI agent governance:

| Specification | Axis | Question Answered | STRIDE Coverage |
| :--- | :--- | :--- | :--- |
| **Actor Chain** ({{!I-D.draft-mw-spice-actor-chain}}) | Identity | WHO delegated to whom? | Spoofing, Repudiation, Elevation of Privilege |
| **Intent Chain** (this document) | Content | WHAT was produced and transformed? | Repudiation, Tampering |
| **Inference Chain** ({{!I-D.draft-mw-spice-inference-chain}}) | Computation | HOW was the output computed? | Spoofing (computational), Tampering (model) |

| Chain | Plane | Token Content | Full Chain | Primary Consumer |
| :--- | :--- | :--- | :--- | :--- |
| **Actor** | Data Plane | Full chain inline | In token | Every Relying Party (real-time authorization) |
| **Intent** | Audit Plane | Merkle root only | External registry | Audit systems, forensic investigators |
| **Inference** | Audit Plane | Merkle root only | External registry | Auditors, compliance systems |

The three chains are independent and composable:

- **Actor Chain Only**: Real-time authorization, access control
- **Intent Chain Only**: Content audit, debugging, filter validation
- **Inference Chain Only**: Computational integrity verification for single-agent systems
- **Actor + Intent**: Full content governance, dispute resolution, regulatory compliance
- **All Three**: Complete "Truth Stack" — identity, content, and computational provenance

1. **Content Provenance**: Cryptographic proof of what each agent produced
2. **Transformation Tracking**: Record of how filters modified content
3. **Tamper Evidence**: Merkle tree structure prevents undetected modification
4. **Efficiency**: Only Merkle root in token; full chain in logs
5. **Scalability**: Append-only logs scale horizontally
6. **Modularity**: Usable independently or with actor chain
7. **Standards Alignment**: Compatible with OAuth 2.0, JWT, SPIFFE

## Design Rationale: Merkle Root in Token

The intent chain uses a Merkle root in the token rather than embedding the full chain inline. The following table summarizes the trade-offs:

| Approach | Token Size | Verification | Privacy | Selective Verify |
| :--- | :--- | :--- | :--- | :--- |
| **A. Full chain in token** | O(n) — grows per entry | Inline, zero latency | Poor — all entries exposed | All-or-nothing |
| **B. Merkle root in token** | O(1) — ~64 bytes | O(log n) per entry | Good — selective disclosure | Single-entry proofs |
| **C. Simple hash of chain** | O(1) — ~64 bytes | O(n) — must rehash all | Good — external storage | Must verify all |
| **D. No provenance in token** | Zero overhead | External lookup | Best — nothing in token | Any pattern |

Approach B is chosen because intent chains can contain 20-50+ entries, making inline embedding impractical for data-plane proxies. The Merkle tree enables O(log n) selective verification of individual entries and provides cryptographic binding between the token and the registry. The actor chain ({{!I-D.draft-mw-spice-actor-chain}}) uses approach A because delegation chains are small (typically 3-5 entries) and every Relying Party needs the full delegation path.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{!RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here.

This document also leverages terminology from OAuth 2.0 Token Exchange
{{!RFC8693}}, the SPICE Architecture {{!I-D.ietf-spice-arch}}, and the
Actor Chain specification {{!I-D.draft-mw-spice-actor-chain}}.

* **Intent Chain**: An ordered sequence of Intent Chain Entries representing
  the complete content journey from originating agent through filters to final
  output within a workflow instance identified by `acti`.

* **Intent Chain Entry**: A record identifying a single content
  transformation, including the agent identity, entry type, content hashes,
  and cryptographic signature.

* **Actor**: A workload, service, application component, agent, or other
  authenticated entity that receives a token, performs work, and MAY
  subsequently act toward another actor. This term is defined in
  {{!I-D.draft-mw-spice-actor-chain}} and used here for consistency.

* **AI Agent**: An autonomous decision-maker that produces content and can
  delegate authority. AI agents appear in both the actor chain (for
  delegation) and the intent chain (for output provenance).

* **Non-Deterministic Filter**: A processor (typically AI-based) whose output
  cannot be reproduced from its input. Examples include AI guardrails,
  LLM-based content rewriters, and semantic classifiers. Both input and output
  MUST be signed.

* **Deterministic Filter**: A processor whose output can be reproduced from
  its input and rules. Examples include schema validators, regex sanitizers,
  and bounds checkers. Output can be re-derived for verification.

* **Intent Registry**: An append-only ordered log storing the full intent
  chain entries, partitioned by `acti`.

* **Actor-chain identifier (`acti`)**: A stable identifier minted once at
  workflow start and retained for the lifetime of the workflow instance.
  Defined in {{!I-D.draft-mw-spice-actor-chain}}. Used by the intent chain as
  the primary partition key for the intent registry and for cross-chain
  correlation.

* **Profile identifier (`actp`)**: Identifies the selected actor-chain profile
  for the workflow instance. Defined in
  {{!I-D.draft-mw-spice-actor-chain}}. The intent chain does not define its
  own profiles but references `actp` for cross-chain correlation.

# Intent Chain Processing

This section defines the normative protocol for constructing and validating
the intent chain. Unlike the Actor Chain, which relies on an Authorization
Server (AS) as a central trust root for delegation, the Intent Chain is a
decoupled, actor-driven audit plane.

## Processing Functions

The following functions MUST be implemented by any SPICE-compliant agent,
registry, or auditor.

### CanonicalizeEntry(E)

To ensure deterministic hashing, every intent chain entry E MUST be
canonicalized using the JSON Canonicalization Scheme (JCS) {{!RFC8785}}
before computing its digest.

### DigestEntry(E)

The `intent_digest` for an entry E is computed as:

1. Create a copy of E.
2. Remove the `intent_digest` and `intent_sig` members from the copy if
   present.
3. Compute the SHA-256 hash of the JCS-canonicalized copy.

### VerifyChainLinkage(E_prev, E_curr)

For any two consecutive entries in the same workflow instance:

```
VerifyChainLinkage(E_prev, E_curr) :=
  (E_prev.output_hash == E_curr.input_hash)
```

## Per-Hop Protocol Procedure

The intent chain advances through actor-driven work. No central infrastructure
is required for individual entry creation.

### 1. Step Proof Generation (Current Actor)

The current actor (agent or filter) performs the following steps locally:

1. **Compute Content Hashes**: Compute the SHA-256 hash of the input content
   (if any) and the resulting output content.
2. **Privacy Constraint (MUST)**: The raw content MUST NOT be shared with the
   Intent Registry or any other infrastructure. Only the content hashes are
   used.
3. **Construct Entry**: Create an intent chain entry E containing `type`,
   `sub`, `input_hash`, `output_hash`, and `iat`.
4. **Sign Entry**:
   a. Compute `DigestEntry(E)`.
   b. Sign the digest using the actor's private key to produce `intent_sig`.
   c. Add `intent_digest` and `intent_sig` to E.
5. **Append to Registry**: The actor appends E to the `intent_registry`
   referenced in its current token.

### 2. Root Commitment (Infrastructure)

While entries are signed by actors, the aggregate `intent_root` in the token 
serves as the formal commitment. If an AS is involved in a subsequent token 
exchange (e.g., to extend the Actor Chain), it SHOULD recompute the `intent_root` 
from the registry state and embed it in the issued JWT.

## Security Properties of Processing

* **AS Privacy**: The AS learns the content hashes and the sequence of agents
  but never sees the raw content.
* **Content Integrity**: Any modification to content between hops breaks the
  linkage (VerifyChainLinkage failure).
* **Non-Repudiation**: Each agent's signature on its entry proves it
  attested to that specific transformation.
* **Tamper Evidence**: The `intent_root` in the JWT binds the forensic
  evidence in the registry to the data-plane token.

# Architecture: Governance Layers

The SPICE governance stack consists of four layers that work together to
ensure workflow integrity:

| Layer | Responsibility | Binding | Threat Mitigation |
| :--- | :--- | :--- | :--- |
| **Workflow (`acti`)** | Lifecycle and identity boundary | `acti`, `sub`, `actp` | DoS, Leakage |
| **Actor Chain (WHO)** | Delegation of authority path | `act`, `actc`, `step_sig` | Spoofing, EoP |
| **Intent Chain (WHAT)** | Content transformation journey | `intent_root`, `intent_sig` | Repudiation, Tampering |
| **Inference Chain (HOW)** | Computational integrity | `inference_root`, `proof_sig` | Comp. Spoofing |

## Relationship to Other Specifications

### Actor Chain ({{!I-D.draft-mw-spice-actor-chain}})

The intent chain depends on the actor chain for identity mapping. Every
`sub` producing an entry in the intent chain MUST be a valid actor in the
corresponding actor chain. The `acti` identifier binds the two chains into a
single verifiable workflow instance.


# Intent Chain Definition

## Entry Types

The intent chain contains two types of entries:

| Entry Type | Determinism | Signed Fields | Type-Specific Fields |
| :--- | :--- | :--- | :--- |
| Non-Deterministic (AI agent output, AI-based filter) | Non-deterministic | `input_hash` + `output_hash` | `model_info` (optional) |
| Deterministic (rule-based filter) | Deterministic | `input_hash` + `output_hash` | `rule_id`, `rule_hash` |

All entry types REQUIRE both `input_hash` and `output_hash`. This uniform structure ensures that every consecutive pair satisfies `entry[i].output_hash == entry[i+1].input_hash`, creating a complete content provenance chain. The cost is approximately 40 bytes per entry in the ordered logs — not in the token itself, which carries only the Merkle root regardless of entry count.

## Non-Deterministic Entries

Non-deterministic entries record outputs from AI agents or AI-based filters whose output cannot be reproduced from the input alone.

**Examples**:

- AI agent outputs (orchestrator, planner, tool agent)
- AI guardrails (Llama Guard, NeMo Guardrails)
- LLM-based content rewriters
- Semantic classifiers

**Properties**:

- Sub is an AI agent or AI-based filter (agents also appear in actor chain)
- Output is non-deterministic (cannot be reproduced)
- `input_hash` and `output_hash` MUST be recorded and signed

**Agent Output Example**:

```json
{
  "type": "non_deterministic",
  "sub": "spiffe://example.com/agent/orchestrator",
  "input_hash": "sha256:fff000...",
  "output_hash": "sha256:abc123...",
  "iat": 1700000010,
  "intent_digest": "sha256:...",
  "intent_sig": "eyJhbGci..."
}
```

**AI Filter Example**:

```json
{
  "type": "non_deterministic",
  "sub": "spiffe://example.com/filter/ai-guardrail",
  "filter_version": "v2.1",
  "input_hash": "sha256:abc123...",
  "output_hash": "sha256:def456...",
  "model_info": {
    "model": "llama-guard-3",
    "categories": ["violence", "pii", "prompt_injection"]
  },
  "iat": 1700000015,
  "intent_digest": "sha256:...",
  "intent_sig": "eyJhbGci..."
}
```

## Deterministic Entries

Deterministic filter entries record transformations by rule-based filters whose output can be reproduced from the input and rules.

**Examples**:

- Schema validators (JSON Schema)
- Regex sanitizers (XSS removal)
- Bounds checkers (amount limits)
- PII redactors (pattern-based)

**Properties**:

- Sub is a rule-based filter
- Output CAN be reproduced from input + rules
- `input_hash` and `output_hash` MUST be recorded and signed
- `rule_id` and `rule_hash` are type-specific signed fields in the log entry, enabling independent re-verification
- Output can be re-derived by re-applying the rule to the input

**Structure**:

```json
{
  "type": "deterministic",
  "sub": "spiffe://example.com/filter/schema-validator",
  "filter_version": "v1.0",
  "input_hash": "sha256:def456...",
  "output_hash": "sha256:ghi789...",
  "rule_id": "ticket-schema-v2",
  "rule_hash": "sha256:rrr...",
  "transform_applied": {
    "fields_validated": ["title", "priority", "amount"],
    "fields_modified": ["priority"],
    "modification": {
      "priority": {
        "from": "critical",
        "to": "medium",
        "reason": "bounds_exceeded"
      }
    }
  },
  "reproducible": true,
  "iat": 1700000016,
  "intent_digest": "sha256:...",
  "intent_sig": "eyJhbGci..."
}
```

## Entry Structure

All intent chain entries share common fields:

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `type` | string | REQUIRED | Entry type: `non_deterministic`, `deterministic` |
| `sub` | string | REQUIRED | SPIFFE ID of the agent or filter |
| `input_hash` | string | REQUIRED | SHA-256 hash of the input content |
| `output_hash` | string | REQUIRED | SHA-256 hash of the output content |
| `iat` | number | REQUIRED | Timestamp when entry was created |
| `intent_digest` | string | REQUIRED | Hash of the canonically serialized entry for Merkle leaf computation |
| `intent_sig` | string | REQUIRED | Signature over `intent_digest` using the agent's or filter's private key |


### `intent_digest` Computation

The `intent_digest` field is computed as the SHA-256 hash of the canonically serialized entry, excluding the `intent_digest` and `intent_sig` fields themselves. This hash serves as the leaf node in the Merkle tree.

For an entry E with fields {type, sub, input_hash, output_hash, iat, ...}:

```
intent_digest = SHA-256(canonical_json(E \ {intent_digest, intent_sig}))
```

Where `canonical_json` follows JSON Canonicalization Scheme (JCS)
{{!RFC8785}} to ensure deterministic serialization.

The `intent_sig` (when REQUIRED) is computed over the `intent_digest` value using the agent's private key:

```
intent_sig = Sign(agent_key, intent_digest)
```

This two-step process ensures that: (a) the digest is stable and independent of signature ordering, and (b) the signature covers all content-relevant fields of the entry.

Additional fields by entry type:

| Field | Entry Types | Description |
| :--- | :--- | :--- |
| `filter_version` | Filters | Version of filter |
| `rule_id` | Deterministic | Identifier of rule applied |
| `rule_hash` | Deterministic | Hash of rule definition |
| `model_info` | Non-deterministic | AI model information |
| `transform_applied` | Filters | Details of transformation |
| `reproducible` | Deterministic | Boolean indicating reproducibility |

# Storage Architecture

## Intent Registry (Ordered Logs)

The intent registry stores immutable intent chain entries as ordered logs.

**Contents**:

- Non-deterministic entries (AI agent outputs, AI-based filters)
- Deterministic entries (rule-based filters)

> Intent registry entries MUST NOT contain OAuth tokens, bearer credentials, or signing keys. Entries contain only content hashes, metadata, agent identities, and entry-level signatures. The token references the registry via the `intent_registry` claim; the registry MUST NOT store or reference the token itself.

**Properties**:

- Append-only (immutable)
- Ordered by offset within workflow instance
- Partitioned by `acti`
- Eventual consistency acceptable

Implementations SHOULD use an append-only log that supports partitioned, ordered retrieval by the token's `acti` claim and provides tamper-evident guarantees (e.g., via hash chaining or inclusion proofs).

**Log Structure**:

```json
{
  "acti": "wf-uuid-12345",
  "offset": 0,
  "entry": {
    "type": "non_deterministic",
    "sub": "spiffe://example.com/agent/A",
    "input_hash": "sha256:prompt...",
    "output_hash": "sha256:abc...",
    "iat": 1700000010,
    "intent_digest": "sha256:...",
    "intent_sig": "eyJ..."
  }
}
```

### Relationship Between `acti` and `jti`

The `acti` is a stable identifier for the workflow instance. It remains
constant as the delegation chain grows through multiple token exchanges, each
of which produces a new token with a distinct `jti`:

```
Workflow instance: acti = "wf-uuid-12345"

  Token Exchange 1 (jti: "tok-aaa")
    User → Agent A
    Intent entries: offset 0 (Agent A output)

  Token Exchange 2 (jti: "tok-bbb")
    Agent A → Agent B
    Intent entries: offset 1 (filter), offset 2 (Agent B output)

  Token Exchange 3 (jti: "tok-ccc")
    Agent B → Agent C
    Intent entries: offset 3 (filter), offset 4 (Agent C output)
```

All intent chain entries share `acti: "wf-uuid-12345"` regardless of which
token exchange produced them. The `acti` value is preserved during each token
exchange as a required claim. During forensic verification, the investigator
retrieves all entries for an `acti` to reconstruct the complete content
journey.

## Merkle Tree Construction

The Merkle tree is constructed from ordered log entries. Leaf nodes are the SHA-256 hashes of canonically serialized intent chain entries. Internal nodes are the SHA-256 hash of the concatenation of their two child hashes. When a level has an odd number of nodes, the last node is promoted to the next level.

See Appendix A for a visual depiction and reference construction algorithm.

## Merkle Root in Token

Only the Merkle root is included in the OAuth token:

```json
{
  "intent_root": "sha256:abc123def456...",
  "intent_alg": "sha256",
  "intent_registry": "https://intent-log.example.com"
}
```

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `intent_root` | string | REQUIRED | Merkle root hash of intent chain |
| `intent_alg` | string | OPTIONAL | Hash algorithm (default: sha256) |
| `intent_registry` | string | REQUIRED | URI of intent registry for proof retrieval |

# Token Structure

## Combined Token Format

The complete token combines actor chain claims and intent chain claims:

```json
{
  "iss": "https://auth.example.com",
  "sub": "user-alice",
  "aud": "https://api.example.com",
  "jti": "tok-aaa-12345",
  "iat": 1700000000,
  "exp": 1700003600,
  "actp": "declared-full",
  "acti": "wf-uuid-12345",

  "act": {
    "iss": "https://auth.example.com",
    "sub": "spiffe://example.com/agent/support",
    "act": {
      "iss": "https://auth.example.com",
      "sub": "spiffe://example.com/agent/orchestrator"
    }
  },

  "intent_root": "sha256:abc123def456789...",
  "intent_registry":
    "https://intent-log.example.com/workflows/wf-uuid-12345"
}
```

## Claim Definitions

### Workflow and Actor Chain Claims

| Claim | Type | Description |
| :--- | :--- | :--- |
| `acti` | string | Actor-chain identifier — stable across token exchanges within a workflow instance. Defined in {{!I-D.draft-mw-spice-actor-chain}} |
| `actp` | string | Profile identifier for the actor chain. Immutable for a given `acti`. Defined in {{!I-D.draft-mw-spice-actor-chain}} |
| `act` | object | Nested actor chain. Outermost `act` identifies the current actor; nested `act` members identify prior actors. Defined in {{!RFC8693}} and profiled by {{!I-D.draft-mw-spice-actor-chain}} |
| `actc` | object | Cumulative commitment state for verified profiles. OPTIONAL. Defined in {{!I-D.draft-mw-spice-actor-chain}} |

### Intent Chain Claims

| Claim | Type | Description |
| :--- | :--- | :--- |
| `intent_root` | string | Merkle root hash of intent chain |
| `intent_alg` | string | Hash algorithm used (default: sha256) |
| `intent_registry` | string | URI for retrieving full chain or proofs (REQUIRED) |

## Examples

### Minimal Token (Actor Chain Only)

```json
{
  "iss": "https://auth.example.com",
  "sub": "user-alice",
  "jti": "tok-bbb-12345",
  "iat": 1700000000,
  "exp": 1700003600,
  "actp": "declared-full",
  "acti": "wf-uuid-12345",

  "act": {
    "iss": "https://auth.example.com",
    "sub": "spiffe://example.com/agent/A"
  }
}
```

### Minimal Token (Intent Chain Only)

```json
{
  "iss": "https://auth.example.com",
  "sub": "user-alice",
  "jti": "tok-ccc-12345",
  "iat": 1700000000,
  "exp": 1700003600,

  "intent_root": "sha256:abc123...",
  "intent_registry":
    "https://intent-log.example.com/workflows/wf-uuid-12345"
}
```

### Full Token (Both Chains)

See (#combined-token-format).

# Verification Procedures

## Request-Time Policy Checks

At request time, the Relying Party performs lightweight checks on the intent chain metadata in the token. Full chain verification is unnecessary on the hot path because:

- The content has already been produced; verifying signatures cannot undo it.
- The Relying Party has the token, not the raw content, so it cannot cross-check content hashes.
- O(n) signature verification per request adds latency without improving authorization decisions.

The Relying Party SHOULD:

1. Verify the JWT outer signature (covers `intent_root` as a signed claim).
2. Check that `intent_root` and `intent_registry` are present (policy: "intent chain coverage required").
3. Apply policy rules against intent chain entry types fetched from the registry (e.g., "must include at least one `deterministic` entry").

The tiered verification table reflects the appropriate level of intent chain checking based on risk:

| Risk Level | Actor Chain | Intent Chain | Use Case |
| :--- | :--- | :--- | :--- |
| Low | Verify JWT signature | Check `intent_root` present | Read operations |
| Medium | Verify JWT signature | Async policy check on entry types | Create/update |
| High | Verify JWT signature + actor sigs | Full forensic verification | Delete, transfer, admin |

## Forensic Verification

Forensic verification is performed after-the-fact by an auditor or dispute resolution system.

1. **Fetch Entries**: Download all intent chain entries for the given `acti` from the `intent_registry`.
2. **Verify Signatures**: For each entry, verify the `intent_sig` using the public key associated with the `sub`. The auditor MUST cross-reference the `sub` with the corresponding actor in the Actor Chain ({{!I-D.draft-mw-spice-actor-chain}}).
3. **Verify Linkage**: Confirm that for every consecutive pair of entries (E_i, E_i+1), `E_i.output_hash == E_i+1.input_hash`.
4. **Recompute Root**: Compute the Merkle root over the ordered list of `intent_digest` values.
5. **Compare Roots**: Compare the recomputed root with the `intent_root` claim in the presented token. If they match, the full intent chain is verified.
6. **Re-derive deterministic outputs**: For `deterministic` entries, retrieve the rule definition matching `rule_hash`, re-apply it to the content matching `input_hash`, and verify the output matches `output_hash`.

## Dispute Resolution Workflow

In the event of a dispute (e.g., "Agent A did not produce that harmful output"):

1. Retrieve the archived token and full intent chain.
2. Locate entries where `sub` matches Agent A's SPIFFE ID.
3. Verify Agent A's `intent_sig` on each of those entries. A valid signature proves Agent A attested to producing that specific `output_hash`.
4. Trace backwards via `input_hash` to find the originating cause (e.g., prompt injection from a prior agent).

## Cross-Chain Binding

When auditing actor and intent chains together, the auditor performs cross-chain binding checks:

For each intent chain entry of type `non_deterministic`: verify that `entry.sub` appears in the nested `act` structure of the token by traversing `VisibleChain(act)`. Verify that `entry.iat` falls within the actor's active window. A mismatch indicates an unregistered agent produced content.

Full two-chain audit is RECOMMENDED for regulatory submissions, dispute resolution, and post-breach forensic analysis.


# Policy Enforcement

## Policy Examples

### Require All Outputs Filtered

Every agent output must be followed by at least one filter:

```
require_filtered_outputs {
    intent_chain := get_intent_chain(input.intent_root)

    agent_outputs := [i |
        intent_chain[i].type == "non_deterministic"]

    every i in agent_outputs {
        # Next entry must be a filter (if not last)
        i < count(intent_chain) - 1
        intent_chain[i + 1].type != "non_deterministic"
    }
}
```

### Require Non-Deterministic Filter for AI Outputs

AI agent outputs must pass through an AI guardrail:

```
require_ai_guardrail {
    intent_chain := get_intent_chain(input.intent_root)

    every i, entry in intent_chain {
        entry.type == "non_deterministic" implies {
            # Must be followed by an entry with AI guardrail model
            some j
            j > i
            intent_chain[j].model_info.model ==
                "llama-guard-3"
        }
    }
}
```

### Verify Specific Transformation Applied

Sensitive fields must be sanitized:

```
require_pii_redaction {
    intent_chain := get_intent_chain(input.intent_root)

    some i
    intent_chain[i].type == "deterministic"
    intent_chain[i].rule_id == "pii-redaction-v1"
}
```

## Integration with Policy Engines

The intent chain claims are designed for consumption by policy engines such as Open Policy Agent (OPA). A policy engine SHOULD:

1. Validate token expiry and revocation status.
2. Verify actor chain integrity using nested `act` and `actp` (per {{!I-D.draft-mw-spice-actor-chain}}).
3. Verify `intent_root` and `intent_registry` are present and non-empty.
4. Evaluate deployment-specific requirements against the intent chain entries (e.g., requiring filtered outputs, specific guardrail models, or PII redaction).

# Threat Model and Security Considerations

The Intent Chain specifically addresses **Tampering** and **Repudiation** in
AI agent workflows. Use of this specification assumes a baseline security
posture (e.g., protected endpoints, secure key storage).

## STRIDE Threat Analysis

| Threat | Attack Scenario | Mitigation |
| :--- | :--- | :--- |
| **S - Spoofing** | Adversary injects entries as a legitimate agent. | Non-deterministic entries MUST be signed by the agent's private key (`intent_sig`). |
| **T - Tampering** | Malicious registry reorders or deletes entries. | The `intent_root` in the token binds the expected registry state. Any modification breaks the Merkle proof. |
| **R - Repudiation** | Agent A claims it never produced harmful content. | Agent A's signature over its `output_hash` provides proof of production. |
| **I - Information Disclosure** | Registry or infrastructure learns sensitive content. | **Privacy-First**: Raw content never leaves the actor; only hashes are stored or transmitted. |
| **D - Denial of Service** | Registry is flooded with entries. | Registry operators SHOULD implement rate limits and retention policies tied to `exp`. |
| **E - Elevation of Privilege** | Agent bypassing filters. | All content MUST have an `input_hash` matching the prior `output_hash`. Unlinked entries denote an unauthorized path. |

## Privacy Considerations

The Intent Chain implements a "Zero-Knowledge" approach to infrastructure:

1. **Actor Local Hashing**: All hashing happens on the original content
   *before* it leaves the agent's secure boundary.
2. **No Central Secrets**: Verification depends on public keys already present
   in the Actor Chain. Infrastructure (AS/Registry) does not need access to
   agent keys.
3. **Selective Disclosure**: Using Merkle proofs, an auditor can verify one
   specific entry (e.g., that Filter X processed the input) without revealing
   the entire intent chain.

## Registry Hosting and Trust

The Registry SHOULD be treated as a semi-trusted append-only log. It does not
need to be trusted for content secrecy (due to hashing) but MUST be trusted for
availability. In federated environments, each domain MAY host its own registry,
with `intent_registry` URIs pointing to the authoritative log for a given hop.

# Implementation Guidance

## Intent Registry Implementation

The intent registry stores immutable intent chain entries. Recommended properties:

- Append-only log structure
- Partitioned by `acti` for isolation
- Configurable retention period
- Merkle root computation triggered on append or at token exchange time

A federated IAM/IdM platform (e.g., Keycloak, Microsoft Entra, Okta, PingFederate) MAY host the intent registry alongside the Actor Chain Registry ({{!I-D.draft-mw-spice-actor-chain}}), since the Authorization Server already mediates token exchanges and can append intent chain entries as a side-effect. Most enterprise IAM/IdM platforms support configurable data stores that can be configured for append-only semantics — see {{!I-D.draft-mw-spice-actor-chain}} Section "Registry Hosting" for detailed requirements.

## Multi-AS Deployments

In deployments involving multiple Authorization Servers (e.g., federated enterprise environments where different ASes serve different organizational domains), the intent registry is shared across all participating ASes. Each AS appends intent chain entries to the same `acti`-partitioned registry, identified by the `acti` claim carried in the token. This works without coordination between ASes because:

- The `acti` value is established at workflow initiation and carried forward unchanged through all token exchanges.
- Each AS appends entries atomically under the workflow's `acti` partition.
- The Merkle root is recomputed at each token exchange time over all entries accumulated so far (by any AS).
- The resulting `intent_root` in the token therefore differs at each hop — each successive AS produces a larger Merkle root reflecting the growing chain. This is expected behavior: a growing root is the normal consequence of an append-only chain and indicates that additional intent entries have been recorded.

This enables cross-domain content provenance tracking without requiring ASes to share keys or coordinate directly — the `acti` partition and append-only log semantics provide the necessary consistency.

## Scalability Considerations

- **Log Partitioning**: `acti`-based partitioning ensures that intent chains for different workflow instances are isolated and can be processed in parallel.
- **Merkle Root Caching**: Computed Merkle roots SHOULD be cached to avoid recomputation on every token exchange.
- **Proof Materialization**: Merkle proofs for recent entries SHOULD be pre-computed and cached for O(1) retrieval.

## Operational Recommendations

- **Retention Policy**: Intent chain logs SHOULD be retained for the maximum audit window required by the deployment's regulatory environment.
- **Monitoring**: Operators SHOULD monitor intent chain append latency and Merkle root computation time.
- **Backup**: Intent chain logs SHOULD be replicated across availability zones for durability.

## Registry Availability

Intent registry unavailability does not affect data-plane operation — the token's AS-signed `intent_root` is sufficient for request-time policy decisions (e.g., "intent chain coverage required"). Per-entry forensic verification is deferred to the audit plane and is not required on the hot path.

However, if the registry is permanently lost, forensic verification becomes impossible. Deployments SHOULD:

- Replicate intent registry entries across availability zones.
- Use append-only log services designed for high durability (e.g., SCITT transparency logs).
- Retain archived tokens (containing `intent_root`) separately from intent chain entries, so that Merkle root commitments survive independently of the registry.
- Define a fail-mode policy: **fail-closed** (reject tokens whose intent chains cannot be verified) for high-risk operations, or **fail-open** (accept the AS-signed token and log the verification gap) for low-risk operations.



# Appendix B: Operational Flows

## Intent Chain Construction

```
  Agent A        Filter        Agent B       Intent
                                             Registry
     |               |               |           |
     | Produce       |               |           |
     | output        |               |           |
     |---------------+---------------+---------->|
     |               |               |  Append   |
     |               |               | non-det   |
     |               |               |   entry   |
     |               |               |           |
     | Send to       |               |           |
     | filter        |               |           |
     |-------------->|               |           |
     |               |               |           |
     |               | Transform     |           |
     |               | content       |           |
     |               |---------------+---------->|
     |               |               |  Append   |
     |               |               | filter    |
     |               |               |   entry   |
     |               |               |           |
     |               | Send to       |           |
     |               | Agent B       |           |
     |               |-------------->|           |
     |               |               |           |
     |               |               | Produce   |
     |               |               | output    |
     |               |               |---------->|
     |               |               |  Append   |
     |               |               | non-det   |
     |               |               |   entry   |
     |               |               |           |
```

## Token Exchange Integration

```
  Agent B          AS          Intent      Actor
                               Registry    Registry
     |               |            |            |
     | Token         |            |            |
     | Exchange      |            |            |
     | Request       |            |            |
     |-------------->|            |            |
     |               |            |            |
     |               | Validate   |            |
     |               | existing   |            |
     |               | act chain  |            |
     |               |            |            |
     |               | Extend     |            |
     |               | act chain  |            |
     |               |------------+----------->|
     |               |            |   Store    |
     |               |            | capability |
     |               |            |            |
     |               | Compute    |            |
     |               | intent_root|            |
     |               |----------->|            |
     |               | Get Merkle |            |
     |               | root       |            |
     |               |<-----------|            |
     |               |            |            |
     | New token     |            |            |
     | with both     |            |            |
     | chains        |            |            |
     |<--------------|            |            |
     |               |            |            |
```

## Request-Time Check at Relying Party

```
  Agent C       Relying       Intent      Actor
                 Party        Registry    Registry
     |               |            |            |
     | Request +     |            |            |
     | Token         |            |            |
     |-------------->|            |            |
     |               |            |            |
     |               | Verify JWT |            |
     |               | signature  |            |
     |               |            |            |
     |               | Verify     |            |
     |               | act chain  |            |
     |               | (per actp) |            |
     |               |            |            |
     |               | Check      |            |
     |               | intent_root|            |
     |               | present    |            |
     |               |            |            |
     |               | Apply      |            |
     |               | policy on  |            |
     |               | entry types|            |
     |               |----------->|            |
     |               | Fetch entry|            |
     |               | types only |            |
     |               |<-----------|            |
     |               |            |            |
     |               | Policy OK: |            |
     |               | Execute    |            |
     |               |            |            |
     | Response      |            |            |
     |<--------------|            |            |
     |               |            |            |
```

# IANA Considerations

## JWT Claim Registration

This document requests registration of the following claims in the "JSON Web Token Claims" registry established by {{!RFC7519}}:

- **Claim Name**: `intent_root`
- **Claim Description**: Merkle root hash of the intent chain for content provenance verification.
- **Change Controller**: IETF
- **Specification Document(s)**: [this document]

- **Claim Name**: `intent_alg`
- **Claim Description**: Hash algorithm used for intent chain Merkle tree construction.
- **Change Controller**: IETF
- **Specification Document(s)**: [this document]

- **Claim Name**: `intent_registry`
- **Claim Description**: URI of the intent registry for proof retrieval.
- **Change Controller**: IETF
- **Specification Document(s)**: [this document]

## CWT Claim Registration

This document requests registration of the following claims in the "CBOR Web Token (CWT) Claims" registry established by {{!RFC8392}}:

- **Claim Name**: `intent_root`
- **Claim Description**: Merkle root hash of the intent chain.
- **CBOR Key**: TBD (e.g., 50)
- **Claim Type**: tstr
- **Change Controller**: IETF
- **Specification Document(s)**: [this document]

- **Claim Name**: `intent_registry`
- **Claim Description**: URI of the intent registry for proof retrieval.
- **CBOR Key**: TBD (e.g., 51)
- **Claim Type**: tstr
- **Change Controller**: IETF
- **Specification Document(s)**: [this document]

- **Claim Name**: `intent_alg`
- **Claim Description**: Hash algorithm used for intent chain Merkle tree construction.
- **CBOR Key**: TBD (e.g., 52)
- **Claim Type**: tstr
- **Change Controller**: IETF
- **Specification Document(s)**: [this document]

# Acknowledgments

The authors would like to thank the participants of the IETF SPICE Working
Group for their valuable feedback and contributions to this specification.

# Appendix B: Operational Flows

## Intent Chain Construction

```
  Agent A        Filter        Agent B       Intent
                                             Registry
     |               |               |           |
     | Produce       |               |           |
     | output        |               |           |
     |---------------+---------------+---------->|
     |               |               |  Append   |
     |               |               | non-det   |
     |               |               |   entry   |
     |               |               |           |
     | Send to       |               |           |
     | filter        |               |           |
     |-------------->|               |           |
     |               |               |           |
     |               | Transform     |           |
     |               | content       |           |
     |               |---------------+---------->|
     |               |               |  Append   |
     |               |               | filter    |
     |               |               |   entry   |
     |               |               |           |
     |               | Send to       |           |
     |               | Agent B       |           |
     |               |-------------->|           |
     |               |               |           |
     |               |               | Produce   |
     |               |               | output    |
     |               |               |---------->|
     |               |               |  Append   |
     |               |               | non-det   |
     |               |               |   entry   |
     |               |               |           |
```

## Token Exchange Integration

```
  Agent B          AS          Intent      Actor
                               Registry    Registry
     |               |            |            |
     | Token         |            |            |
     | Exchange      |            |            |
     | Request       |            |            |
     |-------------->|            |            |
     |               |            |            |
     |               | Validate   |            |
     |               | existing   |            |
     |               | act chain  |            |
     |               |            |            |
     |               | Extend     |            |
     |               | act chain  |            |
     |               |------------+----------->|
     |               |            |   Store    |
     |               |            | capability |
     |               |            |            |
     |               | Compute    |            |
     |               | intent_root|            |
     |               |----------->|            |
     |               | Get Merkle |            |
     |               | root       |            |
     |               |<-----------|            |
     |               |            |            |
     | New token     |            |            |
     | with both     |            |            |
     | chains        |            |            |
     |<--------------|            |            |
     |               |            |            |
```

## Request-Time Check at Relying Party

```
  Agent C       Relying       Intent      Actor
                 Party        Registry    Registry
     |               |            |            |
     | Request +     |            |            |
     | Token         |            |            |
     |-------------->|            |            |
     |               |            |            |
     |               | Verify JWT |            |
     |               | signature  |            |
     |               |            |            |
     |               | Verify     |            |
     |               | act chain  |            |
     |               | (per actp) |            |
     |               |            |            |
     |               | Check      |            |
     |               | intent_root|            |
     |               | present    |            |
     |               |            |            |
     |               | Apply      |            |
     |               | policy on  |            |
     |               | entry types|            |
     |               |----------->|            |
     |               | Fetch entry|            |
     |               | types only |            |
     |               |<-----------|            |
     |               |            |            |
     |               | Policy OK: |            |
     |               | Execute    |            |
     |               |            |            |
     | Response      |            |            |
     |<--------------|            |            |
     |               |            |            |
```



# Merkle Tree Construction Details

## Tree Structure

```
                    intent_root (in JWT)
                          |
                +---------+---------+
                |                   |
          Hash(0-2)              Hash(3-5)
                |                   |
        +-------+-------+   +-------+-------+
        |               |   |               |
     Hash(0-1)      Hash(2) Hash(3-4)    Hash(5)
        |               |       |           |
    +---+---+           |   +---+---+       |
    |       |           |   |       |       |
 Entry0  Entry1     Entry2 Entry3 Entry4  Entry5
 (non-det)(non-det) (det)  (non-det)(det) (non-det)
```

## Reference Construction Algorithm

```python
def compute_merkle_root(entries):
    if len(entries) == 0:
        return None

    # Compute leaf hashes
    hashes = [sha256(canonical_json(entry)) for entry in entries]

    # Build tree bottom-up
    while len(hashes) > 1:
        next_level = []
        for i in range(0, len(hashes), 2):
            if i + 1 < len(hashes):
                combined = sha256(hashes[i] + hashes[i+1])
            else:
                combined = hashes[i]  # Odd node promoted
            next_level.append(combined)
        hashes = next_level

    return hashes[0]
```

# Complete Token Examples

## Full Governance Token

The following example shows a complete token with actor chain and intent chain:

```json
{
  "iss": "https://auth.example.com",
  "sub": "user-alice",
  "aud": "https://api.example.com",
  "jti": "tok-ddd-67890",
  "iat": 1700000000,
  "exp": 1700003600,
  "actp": "declared-full",
  "acti": "wf-uuid-12345",

  "act": {
    "iss": "https://auth.example.com",
    "sub": "spiffe://example.com/agent/support",
    "act": {
      "iss": "https://auth.example.com",
      "sub": "spiffe://example.com/agent/orchestrator"
    }
  },

  "intent_root": "sha256:abc123def456789...",
  "intent_registry":
    "https://intent-log.example.com/workflows/wf-uuid-12345"
}
```

## Corresponding Intent Chain Log Entries

The following entries would be stored in the intent registry for the above token:

```json
[
  {
    "offset": 0,
    "entry": {
      "type": "non_deterministic",
      "sub":
        "spiffe://example.com/agent/orchestrator",
      "input_hash": "sha256:prompt...",
      "output_hash": "sha256:abc...",
      "iat": 1700000010,
      "intent_digest": "sha256:leaf0...",
      "intent_sig": "eyJ..."
    }
  },
  {
    "offset": 1,
    "entry": {
      "type": "non_deterministic",
      "sub":
        "spiffe://example.com/filter/ai-guardrail",
      "filter_version": "v2.1",
      "input_hash": "sha256:abc...",
      "output_hash": "sha256:def...",
      "model_info": {
        "model": "llama-guard-3",
        "categories": ["violence", "pii"]
      },
      "iat": 1700000012,
      "intent_digest": "sha256:leaf1...",
      "intent_sig": "eyJ..."
    }
  },
  {
    "offset": 2,
    "entry": {
      "type": "deterministic",
      "sub":
        "spiffe://example.com/filter/schema-validator",
      "filter_version": "v1.0",
      "input_hash": "sha256:def...",
      "output_hash": "sha256:ghi...",
      "rule_id": "ticket-schema-v2",
      "rule_hash": "sha256:rrr...",
      "reproducible": true,
      "iat": 1700000013,
      "intent_digest": "sha256:leaf2...",
      "intent_sig": "eyJ..."
    }
  },
  {
    "offset": 3,
    "entry": {
      "type": "non_deterministic",
      "sub":
        "spiffe://example.com/agent/support",
      "input_hash": "sha256:ghi...",
      "output_hash": "sha256:jkl...",
      "iat": 1700000030,
      "intent_digest": "sha256:leaf3...",
      "intent_sig": "eyJ..."
    }
  },
  {
    "offset": 4,
    "entry": {
      "type": "deterministic",
      "sub":
        "spiffe://example.com/filter/pii-redactor",
      "filter_version": "v1.2",
      "input_hash": "sha256:jkl...",
      "output_hash": "sha256:mno...",
      "rule_id": "pii-redaction-v1",
      "rule_hash": "sha256:ppp...",
      "reproducible": true,
      "iat": 1700000031,
      "intent_digest": "sha256:leaf4...",
      "intent_sig": "eyJ..."
    }
  },
  {
    "offset": 5,
    "entry": {
      "type": "non_deterministic",
      "sub":
        "spiffe://example.com/agent/tool-executor",
      "input_hash": "sha256:mno...",
      "output_hash": "sha256:pqr...",
      "iat": 1700000050,
      "intent_digest": "sha256:leaf5...",
      "intent_sig": "eyJ..."
    }
  }
]
```
