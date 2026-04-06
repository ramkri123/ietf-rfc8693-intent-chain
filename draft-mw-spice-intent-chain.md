%%%
title = "Cryptographically Verifiable Intent Chain for AI Agent Content Provenance"
abbrev = "SPICE-INTENT-CHAIN"
category = "info"
docname = "draft-mw-spice-intent-chain-00"
ipr = "trust200902"
area = "Security"
workgroup = "SPICE"
keyword = ["intent chain", "spice", "content provenance", "AI agents", "hash chain", "agentic workflows"]
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

In AI agent workflows, content flows through multiple processing stages including AI agents and filters. The intent chain provides a cryptographically verifiable, tamper-evident record of this content journey. The full intent chain is stored as ordered logs, with only the cumulative hash chain commitment included in the OAuth token for efficiency.

Together, the actor chain and intent chain provide complete governance for autonomous AI agent systems, addressing Spoofing, Tampering, Repudiation, and Elevation of Privilege threats in the STRIDE threat model.

{mainmatter}

# Introduction

The Actor Chain extension to {{!RFC8693}} (defined in {{!I-D.draft-mw-spice-actor-chain}}) provides cryptographic proof of delegation paths between AI agents (WHO), but does not address **content provenance** (WHAT was produced and transformed). In AI agent workflows, content flows through multiple agents and filters, each potentially transforming it. Without cryptographic binding between agent identities and their specific content hashes, repudiation claims ("Agent A never produced that output") cannot be disproven.

This specification defines the intent chain — a cumulative hash chain commitment carried in the OAuth token, backed by an append-only registry of signed content transformation entries. Each agent signs `input_hash` + `output_hash` via `intent_step_sig`, creating non-repudiable evidence.

## Relationship to Actor Chain and Inference Chain

| Specification | Axis | Question Answered | STRIDE Coverage |
| :--- | :--- | :--- | :--- |
| **Actor Chain** ({{!I-D.draft-mw-spice-actor-chain}}) | Identity | WHO delegated to whom? | Spoofing, Repudiation, Elevation of Privilege |
| **Intent Chain** (this document) | Content | WHAT was produced and transformed? | Repudiation, Tampering |
| **Inference Chain** ({{!I-D.draft-mw-spice-inference-chain}}) | Computation | HOW was the output computed? | Spoofing (computational), Tampering (model) |

| Chain | Plane | Token Content | Full Chain | Primary Consumer |
| :--- | :--- | :--- | :--- | :--- |
| **Actor** | Data Plane | Full chain inline | In token | Every Relying Party (real-time authorization) |
| **Intent** | Audit Plane | Hash chain commitment only | External registry | Audit systems, forensic investigators |
| **Inference** | Audit Plane | Hash chain commitment only | External registry | Auditors, compliance systems |

The three chains are independent and composable. A deployment MAY use any subset (actor-only, actor+intent, all three). The token carries only an O(1) hash chain commitment (`intc`); full entries reside in an external registry.

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

The `intent_step_hash` for an entry E is computed as:

1. Create a copy of E.
2. Remove the `intent_step_hash` and `intent_step_sig` members from the copy if
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
   b. Sign the digest using the actor's private key to produce `intent_step_sig`.
   c. Add `intent_step_hash` and `intent_step_sig` to E.
5. **Append to Registry**: The actor appends E to the `intent_registry`
   referenced in its current token.

### 2. Root Commitment (Infrastructure)

While entries are signed by actors, the aggregate `intc` commitment in the token 
is signed by the Authorization Server (AS). When the AS performs a token 
exchange (e.g., to extend the Actor Chain), it SHOULD recompute the `intc` 
commitment over all intent chain entries for the current `acti` and include the 
updated commitment object in the new token.

## Security Properties of Processing

* **AS Privacy**: The AS learns the content hashes and the sequence of agents
  but never sees the raw content.
* **Content Integrity**: Any modification to content between hops breaks the
  linkage (VerifyChainLinkage failure).
* **Non-Repudiation**: Each agent's signature on its entry proves it
  attested to that specific transformation.
* **Tamper Evidence**: The `intc` commitment in the JWT binds the forensic
  evidence in the registry to the data-plane token.

## Cross-Chain Dependencies

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

All entry types REQUIRE both `input_hash` and `output_hash`. This uniform structure ensures that every consecutive pair satisfies `entry[i].output_hash == entry[i+1].input_hash`, creating a complete content provenance chain. The cost is approximately 40 bytes per entry in the ordered logs — not in the token itself, which carries only the hash chain commitment regardless of entry count.

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
  "intent_step_hash": "sha256:...",
  "intent_step_sig": "eyJhbGci..."
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
  "intent_step_hash": "sha256:...",
  "intent_step_sig": "eyJhbGci..."
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
  "intent_step_hash": "sha256:...",
  "intent_step_sig": "eyJhbGci..."
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
| `intent_step_hash` | string | REQUIRED | Hash of the canonically serialized entry, used as input to the hash chain computation |
| `intent_step_sig` | string | REQUIRED | Signature over `intent_step_hash` using the agent's or filter's private key |
| `content_envelope` | object | OPTIONAL | Encrypted raw input/output for audit-time content recoverability |

### Sealed Content Layer

Intent registry entries MAY include an OPTIONAL `content_envelope` providing
encrypted raw input and output content for audit-time recoverability. The
sealed content layer enables forensic investigators to reconstruct actual
content during disputes, rather than relying solely on hash verification.

The public layer (hashes, signatures) provides tamper evidence. The sealed
layer provides content recoverability for authorized auditors.

```json
{
  "type": "non_deterministic",
  "sub": "spiffe://example.com/agent/analyst",
  "input_hash": "sha256:fff000...",
  "output_hash": "sha256:abc123...",
  "iat": 1700000010,
  "intent_step_hash": "sha256:...",
  "intent_step_sig": "eyJhbGci...",

  "content_envelope": {
    "enc": "A256GCM",
    "input_ciphertext": "base64url:...",
    "output_ciphertext": "base64url:...",
    "key_ref": "https://kms.example.com/keys/audit-key-v1"
  }
}
```

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `content_envelope.enc` | string | REQUIRED | JWE encryption algorithm (e.g., `A256GCM`) |
| `content_envelope.input_ciphertext` | string | REQUIRED | Encrypted raw input content |
| `content_envelope.output_ciphertext` | string | REQUIRED | Encrypted raw output content |
| `content_envelope.key_ref` | string | REQUIRED | URI referencing the KMS key with access policy |

The `content_envelope` is:

- **Not covered by `intent_step_hash`**: The digest computation excludes `content_envelope` (along with `intent_step_hash` and `intent_step_sig`), so the commitment chain is unaffected.
- **Encrypted at rest**: Only authorized auditors with access to the referenced KMS key can decrypt the content.
- **Verifiable against hashes**: After decryption, `SHA-256(plaintext_input) == input_hash` and `SHA-256(plaintext_output) == output_hash` MUST hold.


### `intent_step_hash` Computation

The `intent_step_hash` field is computed as the SHA-256 hash of the canonically serialized entry, excluding the `intent_step_hash`, `intent_step_sig`, and `content_envelope` fields. This hash serves as the input to the cumulative hash chain computation.

For an entry E with fields {type, sub, input_hash, output_hash, iat, ...}:

```
intent_step_hash = SHA-256(canonical_json(E \ {intent_step_hash, intent_step_sig, content_envelope}))
```

Where `canonical_json` follows JSON Canonicalization Scheme (JCS)
{{!RFC8785}} to ensure deterministic serialization.

The `intent_step_sig` (when REQUIRED) is computed over the `intent_step_hash` value using the agent's private key:

```
intent_step_sig = Sign(agent_key, intent_step_hash)
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
    "intent_step_hash": "sha256:...",
    "intent_step_sig": "eyJ..."
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

## Hash Chain Construction

The intent chain uses a cumulative hash chain constructed from ordered log entries. This is consistent with the Actor Chain's `actc` commitment pattern.

For the first entry (offset 0):

```
chain_hash[0] = SHA-256(intent_step_hash[0])
```

For each subsequent entry (offset i > 0):

```
chain_hash[i] = SHA-256(chain_hash[i-1] || intent_step_hash[i])
```

The final `chain_hash[n]` is the value of `intc.curr` embedded in the token. Any modification, insertion, deletion, or reordering of entries changes the final hash, providing tamper evidence equivalent to the Actor Chain's cumulative commitment.

## Intent Commitment Object in Token (`intc`)

The intent chain commitment is represented as a structured object mirroring the Actor Chain's `actc` pattern. This enables incremental verification without replaying the entire chain:

```json
{
  "intc": {
    "ctx": "intent-chain-commitment-v1",
    "halg": "sha-256",
    "prev": "sha256:prior_commitment...",
    "step_hash": "sha256:latest_entry_hash...",
    "curr": "sha256:cumulative_commitment..."
  },
  "intent_registry": "https://intent-log.example.com"
}
```

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `intc` | object | REQUIRED | Intent chain commitment state |
| `intc.ctx` | string | REQUIRED | Context identifier: `"intent-chain-commitment-v1"` |
| `intc.halg` | string | REQUIRED | Hash algorithm used (e.g., `"sha-256"`) |
| `intc.prev` | string | REQUIRED | Prior commitment value (`intc.curr` from previous exchange, or initial seed) |
| `intc.step_hash` | string | REQUIRED | Hash of the latest `intent_step_sig` bytes: `b64url(Hash(intent_step_sig_bytes))` |
| `intc.curr` | string | REQUIRED | Current cumulative commitment: `b64url(Hash(canonical({ctx, halg, prev, step_hash})))` |
| `intent_registry` | string | REQUIRED | URI of intent registry for full chain retrieval |

# Token Structure

## Intent Evidence in Actor Chain Claims

When Actor Chain and Intent Chain are used together, the `act` claim structure
MAY carry OPTIONAL `input_hash` and `output_hash` fields. These provide inline
structural evidence of content boundaries at each delegation hop.

### Extension Claim Definitions

| Claim | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `input_hash` | string | OPTIONAL | SHA-256 hash of the content received by this actor at the start of its processing segment |
| `output_hash` | string | OPTIONAL | SHA-256 hash of the content produced by this actor at the end of its processing segment |

These claims are defined as extensions to the `act` object specified in
{{!RFC8693}} and profiled by {{!I-D.draft-mw-spice-actor-chain}}. The Actor
Chain specification already defines `act` as an extensible object; these
extension claims do not require changes to Actor Chain normative text.

### Cross-Hop Verification Rule

When both `input_hash` and `output_hash` are present in adjacent `act` entries,
the following structural invariant MUST hold:

```
act[i].output_hash == act[i+1].input_hash
```

A violation of this invariant indicates that the content received by the
downstream actor differs from what the upstream actor produced — i.e., a content
integrity break occurred between actor boundaries.

### Relationship to Intent Chain Registry Entries

The inline `act` hashes represent **segment boundaries** — the content state at
the start and end of each actor's processing. The Intent Chain Registry entries
represent **segment internals** — the detailed step-by-step transformations
within each actor's processing segment. An actor may produce multiple intent
chain entries (e.g., LLM generation followed by content filter) between its
`input_hash` and `output_hash`.

### Three-Tier Evidence Model

| Tier | Plane | Evidence | Verification | Use Case |
| :--- | :--- | :--- | :--- | :--- |
| **Structural** | Data Plane | `input_hash`/`output_hash` in `act` | O(1) per hop | Cross-AS content linkage |
| **Commitment** | Data Plane | `intc` (commitment object) in token | O(1) presence check | Tamper-evidence binding |
| **Forensic** | Audit Plane | Full entries in Intent Registry | O(n) deep audit | Dispute resolution, compliance |

### Multi-AS Motivation

In large enterprise deployments, a single workflow frequently crosses multiple
Authorization Server (AS) boundaries (e.g., during mergers & acquisitions,
business unit autonomy, multi-cloud, or regulatory segmentation). When ASes do
not share a common Intent Registry, the inline `input_hash`/`output_hash` in
the `act` claim provide a self-contained mechanism for verifying content
integrity at trust boundaries. Each AS acts as a local Trusted Third Party,
attesting to the content boundaries of the delegation it mediates — a pattern
we term the **Federated TTP Chain**.

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
    "input_hash": "sha256:e3b0c44298fc1c...",
    "output_hash": "sha256:7d865e959b2466...",
    "act": {
      "iss": "https://auth.example.com",
      "sub": "spiffe://example.com/agent/orchestrator",
      "input_hash": "sha256:a1b2c3d4e5f6...",
      "output_hash": "sha256:e3b0c44298fc1c..."
    }
  },

  "intc": {
    "ctx": "intent-chain-commitment-v1",
    "halg": "sha-256",
    "prev": "sha256:prior_commitment...",
    "step_hash": "sha256:latest_entry...",
    "curr": "sha256:abc123def456789..."
  },
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
| `intc` | object | Intent chain commitment state object mirroring `actc` structure (REQUIRED) |
| `intent_registry` | string | URI for retrieving full chain entries (REQUIRED) |

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

  "intc": {
    "ctx": "intent-chain-commitment-v1",
    "halg": "sha-256",
    "prev": "sha256:initial_seed...",
    "step_hash": "sha256:entry_hash...",
    "curr": "sha256:abc123..."
  },
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

1. Verify the JWT outer signature (covers `intc` as a signed claim).
2. Check that `intc` and `intent_registry` are present (policy: "intent chain coverage required").
3. Apply policy rules against intent chain entry types fetched from the registry (e.g., "must include at least one `deterministic` entry").

The tiered verification table reflects the appropriate level of intent chain checking based on risk:

| Risk Level | Actor Chain | Intent Chain | Use Case |
| :--- | :--- | :--- | :--- |
| Low | Verify JWT signature | Check `intc` present | Read operations |
| Medium | Verify JWT signature | Async policy check on entry types | Create/update |
| High | Verify JWT signature + actor sigs | Full forensic verification | Delete, transfer, admin |

## Forensic Verification

Forensic verification is performed after-the-fact by an auditor or dispute resolution system.

1. **Fetch Entries**: Download all intent chain entries for the given `acti` from the `intent_registry`.
2. **Verify Signatures**: For each entry, verify the `intent_step_sig` using the public key associated with the `sub`. The auditor MUST cross-reference the `sub` with the corresponding actor in the Actor Chain ({{!I-D.draft-mw-spice-actor-chain}}).
3. **Verify Linkage**: Confirm that for every consecutive pair of entries (E_i, E_i+1), `E_i.output_hash == E_i+1.input_hash`.
4. **Recompute Chain Hash**: Starting from the first entry, compute the cumulative hash chain: `chain_hash[0] = SHA-256(intent_step_hash[0])`, then `chain_hash[i] = SHA-256(chain_hash[i-1] || intent_step_hash[i])` for each subsequent entry.
5. **Compare Commitments**: Compare the final recomputed `chain_hash[n]` with `intc.curr` in the presented token. If they match, the full intent chain is verified.
6. **Re-derive deterministic outputs**: For `deterministic` entries, retrieve the rule definition matching `rule_hash`, re-apply it to the content matching `input_hash`, and verify the output matches `output_hash`.

## Dispute Resolution Workflow

In the event of a dispute (e.g., "Agent A did not produce that harmful output"):

1. Retrieve the archived token and full intent chain.
2. Locate entries where `sub` matches Agent A's SPIFFE ID.
3. Verify Agent A's `intent_step_sig` on each of those entries. A valid signature proves Agent A attested to producing that specific `output_hash`.
4. Trace backwards via `input_hash` to find the originating cause (e.g., prompt injection from a prior agent).

## Cross-Chain Binding

When auditing actor and intent chains together, the auditor performs cross-chain binding checks:

For each intent chain entry of type `non_deterministic`: verify that `entry.sub` appears in the nested `act` structure of the token by traversing `VisibleChain(act)`. Verify that `entry.iat` falls within the actor's active window. A mismatch indicates an unregistered agent produced content.

Full two-chain audit is RECOMMENDED for regulatory submissions, dispute resolution, and post-breach forensic analysis.


# Security Considerations

The intent chain addresses **Tampering** and **Repudiation** in AI agent workflows.

## STRIDE Threat Analysis

| Threat | Attack Scenario | Mitigation |
| :--- | :--- | :--- |
| **Spoofing** | Adversary injects entries as a legitimate agent | Non-deterministic entries MUST be signed (`intent_step_sig`) |
| **Tampering** | Registry reorders or deletes entries | `intc` commitment in token binds expected registry state |
| **Repudiation** | Agent claims it never produced harmful content | Agent's signature over `output_hash` proves production |
| **Info Disclosure** | Infrastructure learns sensitive content | Raw content never leaves actor; only hashes stored |
| **DoS** | Registry flooded with entries | Rate limits and retention policies |
| **Elevation of Privilege** | Agent bypasses filters | `input_hash` linkage detects unauthorized paths |

## Privacy Considerations

All hashing happens locally before content leaves the agent's boundary. Verification depends on public keys from the Actor Chain; infrastructure does not need agent keys. The `content_envelope` (when present) is encrypted at rest and accessible only to authorized auditors.

## Registry Trust

The registry is semi-trusted: not trusted for content secrecy (due to hashing) but MUST be trusted for availability. Registry unavailability does not affect data-plane operation — the token's `intc` commitment suffices for request-time policy. Forensic verification is deferred to the audit plane.

# Implementation Guidance

The intent registry stores immutable intent chain entries as an append-only log, partitioned by `acti`. A federated IAM/IdM platform MAY host the intent registry alongside the Actor Chain Registry — see {{!I-D.draft-mw-spice-actor-chain}} Section "Registry Hosting" for requirements.

In multi-AS deployments, each AS appends entries under the workflow's `acti` partition. The hash chain commitment is recomputed at each token exchange over all entries accumulated so far; `intc.curr` therefore grows at each hop. When ASes do not share a registry, inline `input_hash`/`output_hash` in `act` claims provide a self-contained **Federated TTP Chain** for cross-domain content verification.

Deployments SHOULD replicate intent chain entries across availability zones, cache computed hash chain commitments, and define fail-mode policy (fail-closed for high-risk, fail-open for low-risk operations).





# IANA Considerations

## JWT Claim Registration

This document requests registration of the following claims in the "JSON Web Token Claims" registry established by {{!RFC7519}}:

- **Claim Name**: `intc`
- **Claim Description**: Intent chain commitment state object containing cumulative hash chain commitment for content provenance verification.
- **Change Controller**: IETF
- **Specification Document(s)**: [this document]

- **Claim Name**: `intent_registry`
- **Claim Description**: URI of the intent registry for full chain retrieval.
- **Change Controller**: IETF
- **Specification Document(s)**: [this document]

## CWT Claim Registration

This document requests registration of the following claims in the "CBOR Web Token (CWT) Claims" registry established by {{!RFC8392}}:

- **Claim Name**: `intc`
- **Claim Description**: Intent chain commitment state object containing cumulative hash chain commitment.
- **CBOR Key**: TBD (e.g., 50)
- **Claim Type**: map
- **Change Controller**: IETF
- **Specification Document(s)**: [this document]

- **Claim Name**: `intent_registry`
- **Claim Description**: URI of the intent registry for full chain retrieval.
- **CBOR Key**: TBD (e.g., 51)
- **Claim Type**: tstr
- **Change Controller**: IETF
- **Specification Document(s)**: [this document]

# Acknowledgments

The authors would like to thank the participants of the IETF SPICE Working
Group for their valuable feedback and contributions to this specification.


