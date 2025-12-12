# Secure Anonymous Complaint Submission Protocol
## Design Document

**Author:** [Your Name]  
**Date:** November 2024  
**Course:** CS 525/625 - Cryptography

---

## 1. Executive Summary

This document describes a secure anonymous complaint submission protocol that enables users to submit complaints, feedback, or reports anonymously while ensuring authentication, uniqueness, and verifiability. The protocol combines **Zero-Knowledge Proofs (zk-SNARKs)** and **Blind Signatures** to achieve strong security properties.

### 1.1 Core Security Requirements

- **Anonymity**: No party (including administrators) can link a complaint to a specific user
- **Authentication**: Only authorized users can submit complaints
- **One-per-user**: Each user can submit exactly one complaint per reporting round
- **Verifiability**: Anyone can verify that all valid complaints were included and no invalid ones were injected

---

## 2. Protocol Overview

### 2.1 High-Level Architecture

The protocol consists of four main phases:

1. **Setup Phase**: Authority generates cryptographic keys and builds Merkle tree of authorized users
2. **Registration Phase**: Users obtain anonymous credentials via blind signatures
3. **Submission Phase**: Users submit complaints with zero-knowledge proofs
4. **Verification Phase**: Public verification of all submissions

### 2.2 Cryptographic Primitives

- **RSA Blind Signatures**: For anonymous credential issuance
- **Merkle Trees**: For efficient membership proofs
- **Zero-Knowledge Proofs (zk-SNARKs)**: For proving credential validity without revealing identity
- **Nullifiers**: For preventing double submissions

---

## 3. Detailed Protocol Specification

### 3.1 Setup Phase

**Participants**: Authority

**Steps**:

1. Authority generates RSA key pair $(n, e, d)$ where:
   - $n = p \cdot q$ (RSA modulus)
   - $e$ is public exponent
   - $d$ is private exponent

2. Authority creates list of authorized users $U = \{u_1, u_2, ..., u_n\}$

3. **User Commitment Phase** (Critical for ZK-proof binding):
   - Each user $u_i$ generates secret $s_i$ and computes commitment: $C_i = H(u_i || s_i)$
   - Users send commitments $\{C_1, C_2, ..., C_n\}$ to authority
   - Authority receives commitments but does NOT learn secrets $s_i$

4. For each user $u_i$:
   - Use commitment $C_i = H(u_i || s_i)$ as leaf identifier
   - Store Merkle path $\pi_i$ for user

5. Build Merkle tree $MT$ with leaves $\{C_1, C_2, ..., C_n\}$ where $C_i = H(u_i || s_i)$

**IMPORTANT**: Building the tree from $H(u_i || s_i)$ instead of $H(u_i)$ binds all ZK-proof components together:
- Merkle path proves membership of $H(u_i || s_i)$
- RSA signature is on $H(u_i || s_i)$
- Nullifier uses $s_i$: $N = H(s_i || \text{round\_id})$
This ensures the same secret $s_i$ is used throughout, preventing proof component mixing attacks.

6. Publish public parameters:
   - RSA public key: $(n, e)$
   - Merkle root: $R = \text{root}(MT)$
   - Tree depth: $d$

**Output**: Public parameters $PP = (n, e, R, d)$

**Note on RSA Signatures**: For production use, RSA signatures should use padding schemes (e.g., RSA-PSS or RSA-PKCS#1 v1.5) to prevent:
- Small message recovery attacks
- Homomorphic signature forgery (computing $\text{sign}(m_1) \cdot \text{sign}(m_2) = \text{sign}(m_1 \cdot m_2)$)
- Non-uniform distribution across the modulus

Blind signatures with padding are more complex but still possible. This implementation uses raw RSA for simplicity, but the design should specify padding for production deployments.

### 3.2 Registration Phase

**Participants**: User $u_i$, Authority

**Goal**: User obtains anonymous credential without revealing identity to authority

**Steps**:

1. **User → Authority**: Registration request
   - User computes token: $m = H(u_i || s_i) \bmod n$ (matches Merkle tree leaf)
   - User generates random blinding factor: $r \xleftarrow{\$} \mathbb{Z}_n^*$
   - User blinds token: $m' = m \cdot r^e \bmod n$
   - User sends: $(m', \pi_i)$ where $\pi_i$ is Merkle path for $H(u_i || s_i)$

2. **Authority**: Verifies and signs
   - Authority verifies Merkle path $\pi_i$ against root $R$
   - If valid, authority signs: $\sigma' = (m')^d \bmod n$
   - Authority sends: $\sigma'$

3. **User**: Unblinds signature
   - User computes: $\sigma = \sigma' \cdot r^{-1} \bmod n$
   - User verifies: $m = \sigma^e \bmod n$
   - User stores credential: $C_i = (\sigma, \pi_i, s_i)$

**Security Properties**:
- Authority never sees unblinded token $m$
- User's identity remains anonymous during registration
- Merkle path proves authorization without revealing position

### 3.3 Submission Phase

**Participants**: User $u_i$, Bulletin Board

**Goal**: User submits complaint anonymously with proof of authorization

**Steps**:

1. User computes nullifier: $N = H(s_i || \text{round\_id})$

2. User generates zero-knowledge proof $\pi_{zk}$ proving:
   - "I know $(\sigma, s_i, \pi_i)$ such that:
     - $\sigma^e = H(u_i || s_i) \bmod n$ (valid credential)
     - $\pi_i$ is valid Merkle path to root $R$ for $H(u_i || s_i)$
     - $N = H(s_i || \text{round\_id})$ (nullifier computation)"
   
   **Critical Binding**: All three components use the same secret $s_i$:
   - Merkle path proves membership of $H(u_i || s_i)$
   - Signature is on $H(u_i || s_i)$
   - Nullifier uses $s_i$ directly
   
   This cryptographic binding prevents mixing proof components from different credentials.

3. User submits to bulletin board:
   - Complaint text: $C$
   - Round ID: $\text{round\_id}$
   - Nullifier: $N$
   - ZK-proof: $\pi_{zk}$

**Security Properties**:
- ZK-proof reveals nothing about user identity
- Nullifier prevents double submissions (same user, same round)
- No interaction with authority needed

### 3.4 Verification Phase

**Participants**: Verifier (anyone), Bulletin Board

**Goal**: Verify all submissions are valid and no duplicates exist

**Steps**:

1. For each submission $(C, N, \pi_{zk})$:
   - Verify ZK-proof $\pi_{zk}$ using public parameters
   - Check nullifier $N$ not in used nullifiers set
   - Verify complaint format is valid

2. If all checks pass:
   - Add nullifier to used set
   - Accept submission

3. Batch verification:
   - Verify all submissions in batch
   - Ensure no duplicate nullifiers
   - Verify all proofs are valid

**Security Properties**:
- Public verifiability (anyone can verify)
- Prevents double submissions
- Ensures all valid complaints are included

---

## 4. Security Analysis

### 4.1 Anonymity

**Definition**: No adversary can link a complaint to a specific user with probability better than random guessing.

**Analysis**:
- **Blind Signatures**: Authority never sees unblinded token, preventing linking during registration
- **ZK-Proofs**: Reveal only that user has valid credential, not which user
- **Nullifiers**: Computed from secret, cannot be linked to user identity
- **Anonymity Set**: All authorized users (size = $n$)

**Threat Model**:
- Honest-but-curious authority: Cannot link submissions to users
- External adversary: Cannot determine submitter identity
- Colluding users: Cannot identify other submitters

### 4.2 Authentication

**Definition**: Only authorized users can submit valid complaints.

**Analysis**:
- Merkle tree membership proves authorization
- Blind signature proves credential was issued by authority
- ZK-proof verifies credential validity without revealing identity

**Attack Resistance**:
- Unauthorized users: Cannot generate valid Merkle path
- Credential theft: Requires secret $s_i$ to create nullifier
- Forged credentials: Cannot create valid RSA signature without private key

### 4.3 One-per-user Enforcement

**Definition**: Each user can submit at most one complaint per round.

**Analysis**:
- Nullifier $N = H(s_i || \text{round\_id})$ is deterministic
- Same user, same round → same nullifier
- Bulletin board tracks used nullifiers
- Duplicate nullifiers are rejected

**Attack Resistance**:
- Double submission: Detected via nullifier collision
- Sybil attacks: Prevented by Merkle tree membership (requires authorized user)
- Replay attacks: Prevented by round ID in nullifier

**Design Consideration**: The requirement for one complaint per user per round may be too restrictive for some use cases (e.g., ethics complaint systems where multiple incidents should be reportable). Consider:
- Allowing multiple complaints per user per round (tracked via different nullifiers)
- Using complaint categories or types to allow multiple submissions
- Implementing a complaint limit (e.g., maximum 3 complaints per round per user)

### 4.4 Proof Component Binding

**Definition**: All components of the ZK-proof must be cryptographically bound to the same secret.

**Analysis**:
- **Problem**: If Merkle tree uses $H(u_i)$ but signature uses $H(u_i || s_i)$, proof components are not bound
- **Attack**: Attacker could mix valid Merkle path from one user with signature from another
- **Solution**: Build Merkle tree from $H(u_i || s_i)$, ensuring:
  - Merkle path proves membership of $H(u_i || s_i)$
  - Signature is on $H(u_i || s_i)$
  - Nullifier uses $s_i$: $N = H(s_i || \text{round\_id})$
- All three components now cryptographically linked via the same secret $s_i$

**Security Guarantee**: The binding ensures that a valid proof can only be created by someone who knows the secret $s_i$ that matches both the Merkle tree membership and the signature.

### 4.5 Verifiability

**Definition**: Anyone can verify that all valid complaints were included and no invalid ones were injected.

**Analysis**:
- ZK-proofs are publicly verifiable
- Nullifier set is public
- All submissions are stored on bulletin board
- Batch verification ensures completeness

**Verification Capabilities**:
- Verify individual submission validity
- Verify no duplicate submissions
- Verify all submissions in a round
- Audit complete submission history

---

## 5. Threat Model

### 5.1 Adversary Capabilities

**Type 1: Honest-but-Curious Authority**
- Follows protocol correctly
- Attempts to learn user identities
- Cannot break anonymity (blind signatures prevent this)

**Type 2: Malicious Users**
- May attempt to submit multiple complaints
- May attempt to forge credentials
- May attempt to identify other submitters
- Prevented by nullifiers and ZK-proofs

**Type 3: External Adversary**
- Observes network traffic
- May attempt to link submissions
- Cannot break anonymity (ZK-proofs hide identity)

**Type 4: Compromised Authority**
- Has access to private key
- Can issue credentials to unauthorized users
- Cannot link existing submissions to users (blind signatures)

### 5.2 Attack Vectors

1. **Timing Attacks**: Submission timing could reveal identity
   - **Mitigation**: Use mix networks or delay submissions

2. **Network Analysis**: Traffic analysis could link submissions
   - **Mitigation**: Use Tor or similar anonymization network

3. **Side-Channel Attacks**: Implementation leaks could reveal secrets
   - **Mitigation**: Constant-time implementations, secure hardware

4. **Collusion**: Authority and verifier collude
   - **Mitigation**: Distributed bulletin board (blockchain)

---

## 6. Implementation Considerations

### 6.1 ZK-Proof Implementation

**Current Implementation**: Simplified commitment-based proof

**Full Implementation**: Use zk-SNARKs (e.g., Circom + snarkjs)
- Circuit design for credential verification
- Merkle path verification in circuit
- Nullifier computation in circuit
- **Critical**: Circuit must verify all components use same secret $s_i$
- Trusted setup (or use STARKs for transparent setup)

**Proof Binding**: The zk-SNARK circuit must enforce that:
- Merkle path is for $H(u_i || s_i)$
- Signature verifies for $H(u_i || s_i)$
- Nullifier is $H(s_i || \text{round\_id})$
- All use the same secret $s_i$ (binding constraint)

### 6.2 RSA Signature Padding

**Current Implementation**: Raw RSA signatures (no padding)

**Security Issues**:
- Small messages vulnerable to recovery
- Homomorphic property: $\text{sign}(m_1) \cdot \text{sign}(m_2) = \text{sign}(m_1 \cdot m_2)$
- Non-uniform distribution across modulus

**Production Requirement**: Use RSA-PSS (Probabilistic Signature Scheme) or RSA-PKCS#1 v1.5

**Blind Signature Challenge**: Padding with blind signatures is complex but possible:
- PSS padding can be applied before blinding
- Requires careful implementation to maintain blindness
- Standard libraries (e.g., PyCryptodome) support PSS with proper setup

**Note**: This implementation uses raw RSA for simplicity, but production deployments MUST use padding.

### 6.3 Bulletin Board

**Current Implementation**: Centralized bulletin board

**Full Implementation**: Distributed system
- Blockchain-based (e.g., Ethereum)
- Ensures immutability
- Public verifiability
- No single point of failure

### 6.3 Scalability

**Merkle Tree**: O(log n) proof size, efficient for large user sets

**ZK-Proofs**: Constant verification time, independent of user set size

**Nullifiers**: O(1) lookup using hash table

**Bottlenecks**:
- Registration requires interaction with authority
- ZK-proof generation (can be precomputed)

### 6.5 Membership Changes and Tree Rebuilding

**Problem**: Merkle tree must be rebuilt when membership changes, requiring:
- All users to re-register with new Merkle paths
- New round to be started (old credentials invalidated)
- Coordination overhead

**Impact**:
- In dynamic environments (schools, corporations), membership changes daily
- Frequent tree rebuilding causes system churn
- Users must re-register frequently

**Solutions**:
1. **Round-based Membership**: Only update membership at round boundaries
   - New users wait until next round
   - Removed users' credentials expire at round end
   - Reduces churn but delays access

2. **Sparse Merkle Trees**: Use sparse Merkle trees for efficient updates
   - O(log n) update time instead of O(n) rebuild
   - Allows incremental membership changes
   - More complex implementation

3. **Credential Expiration**: Issue time-limited credentials
   - Credentials expire after fixed period
   - Users re-register periodically
   - Balances security and convenience

4. **Membership Windows**: Allow membership changes only during specific periods
   - E.g., monthly membership update windows
   - Reduces frequency of tree rebuilding
   - Requires planning ahead

**Recommendation**: For production systems, implement round-based membership with sparse Merkle trees for better scalability.

---

## 7. Trade-offs and Limitations

### 7.1 Trust Assumptions

- **Authority Trust**: Must honestly issue credentials (cannot be fully eliminated)
- **Bulletin Board Trust**: Must correctly store and serve submissions (mitigated by distribution)

### 7.2 Limitations

1. **Registration Interaction**: Users must interact with authority (one-time cost)
2. **ZK-Proof Complexity**: Full zk-SNARK implementation is complex
3. **Revocation**: Difficult to revoke credentials without breaking anonymity
4. **Timing Attacks**: Protocol doesn't prevent timing-based de-anonymization

### 7.3 Improvements

1. **Distributed Authority**: Use threshold signatures to distribute trust
2. **Transparent Setup**: Use STARKs instead of SNARKs (no trusted setup)
3. **Revocation Mechanism**: Add credential expiration or revocation lists
4. **Mix Networks**: Integrate with mix networks for stronger anonymity

---

## 8. Protocol Flow Diagram

```
┌─────────┐
│Authority│
└────┬─────┘
     │ 1. Setup: Generate keys, build Merkle tree
     │    Publish: (n, e, R)
     │
     ▼
┌─────────────┐
│Public Params│
└──────┬──────┘
       │
       │ 2. Registration
       │
┌──────▼──────┐         ┌─────────┐
│    User     │────────▶│Authority│
│             │ m', π   │         │
└──────┬──────┘         └────┬────┘
       │                     │ σ'
       │◀─────────────────────┘
       │ Unblind: σ
       │ Store: (σ, π, s)
       │
       │ 3. Submission
       │
       ▼
┌─────────────┐
│   Compute   │
│  Nullifier  │
│  ZK-Proof   │
└──────┬──────┘
       │
       │ Submit: (C, N, π_zk)
       │
       ▼
┌─────────────┐
│   Bulletin  │
│    Board    │
└──────┬──────┘
       │
       │ 4. Verification
       │
       ▼
┌─────────────┐
│  Verifier    │
│  (Public)   │
└─────────────┘
```

---

## 9. Mathematical Formalization

### 9.1 Notation

- $H$: Cryptographic hash function
- $(n, e, d)$: RSA key pair
- $MT$: Merkle tree
- $R$: Merkle root
- $\pi_i$: Merkle path for user $i$
- $\sigma$: RSA signature
- $N$: Nullifier
- $\pi_{zk}$: Zero-knowledge proof

### 9.2 Protocol Steps (Formal)

**Setup**:
$$PP = \text{Setup}(U) = (n, e, R, d)$$

**Registration**:
$$C_i = H(u_i || s_i) \quad \text{(user commitment)}$$
$$m = H(u_i || s_i) \bmod n \quad \text{(token matches commitment)}$$
$$m' = m \cdot r^e \bmod n \quad \text{(blinding)}$$
$$\sigma' = (m')^d \bmod n \quad \text{(authority signs)}$$
$$\sigma = \sigma' \cdot r^{-1} \bmod n \quad \text{(unblinding)}$$

**Submission**:
$$N = H(s_i || \text{round\_id})$$
$$\pi_{zk} = \text{Prove}((\sigma, s_i, \pi_i) : \sigma^e = H(u_i || s_i) \bmod n \land \text{valid\_path}(\pi_i, H(u_i || s_i), R) \land N = H(s_i || \text{round\_id}))$$

**Binding Constraint**: All components must use the same secret $s_i$:
- Merkle path is for $H(u_i || s_i)$
- Signature is on $H(u_i || s_i)$
- Nullifier uses $s_i$

**Verification**:
$$\text{Verify}(\pi_{zk}, PP) \land N \notin \text{used\_nullifiers}$$

---

## 10. Conclusion

This protocol provides a secure, anonymous complaint submission system with strong cryptographic guarantees. The combination of blind signatures and zero-knowledge proofs achieves the required security properties while maintaining practical efficiency.

**Key Strengths**:
- Strong anonymity guarantees
- Efficient verification
- Public verifiability
- Prevents double submissions

**Areas for Future Work**:
- Full zk-SNARK implementation
- Distributed bulletin board
- Credential revocation mechanism
- Timing attack mitigation

---

## References

1. Chaum, D. (1983). Blind signatures for untraceable payments. *Advances in Cryptology*.
2. Ben-Sasson, E., et al. (2014). Zerocash: Decentralized anonymous payments from Bitcoin. *IEEE Security & Privacy*.
3. Merkle, R. C. (1988). A digital signature based on a conventional encryption function. *CRYPTO*.

