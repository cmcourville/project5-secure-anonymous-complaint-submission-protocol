# Usage Guide

This guide provides detailed code examples for using the protocol programmatically. For installation and quick start instructions, see [README.md](README.md).

## Overview

This guide shows how to use each phase of the protocol in your own code:
1. **Setup Phase**: Authority initializes the system
2. **Registration Phase**: Users obtain anonymous credentials
3. **Submission Phase**: Users submit complaints
4. **Verification Phase**: Public verification of submissions

## Using the Protocol

### Setup Phase

**Important**: Authority only knows public user IDs, NOT secrets. Users generate their own secrets during registration.

```python
from implementation.setup import AuthoritySetup

# Initialize authority
authority = AuthoritySetup(key_size=2048)

# Generate RSA keys
private_key, public_key = authority.generate_rsa_keys()

# Add authorized users (public IDs only, no secrets!)
user_ids = ['student1', 'student2', 'student3']
authority.add_authorized_users(user_ids)

# Build Merkle tree from public identifiers
root = authority.build_merkle_tree()

# Get public parameters to publish
params = authority.get_public_parameters()
print(f"Merkle root: {params['merkle_root']}")
print(f"RSA public key: n={params['rsa_public_key']['n']}, e={params['rsa_public_key']['e']}")
```

### Registration Phase

**Important**: User generates their own secret. Authority never learns it.

```python
from implementation.registration import RegistrationProtocol
from Crypto.Random import get_random_bytes

# User generates their own secret (authority never learns this!)
user_id = 'student1'
secret = get_random_bytes(32)  # 32 bytes = 256 bits

# Authority provides Merkle path for public identifier
merkle_path = authority.get_user_merkle_path(0)  # Index of user in authorized list
merkle_root = authority.merkle_tree.root
rsa_n = authority.rsa_key.n
rsa_e = authority.rsa_key.e

# Register user (authority signs blinded token without seeing secret)
credential = RegistrationProtocol.register_user(
    user_id=user_id,
    secret=secret,  # User's secret, authority never sees unblinded token
    merkle_path=merkle_path,
    merkle_root=merkle_root,
    rsa_n=rsa_n,
    rsa_e=rsa_e,
    authority_signer=authority.sign_blinded_token
)

# Store credential and secret securely
# Note: credential does NOT contain secret - user must store it separately
print(f"Credential obtained: signature={credential['signature']}")
print(f"User secret (store securely): {secret.hex()}")
```

### Submission Phase

**Important**: User must provide their secret separately. It's NOT stored in the credential.

```python
from implementation.submission import ComplaintSubmission

# Create submission handler
# IMPORTANT: User must provide secret separately (stored securely by user)
submission_handler = ComplaintSubmission(
    credential,  # From registration (does NOT contain secret)
    secret,      # User's secret (stored separately, unknown to authority)
    rsa_n=authority.rsa_key.n,
    rsa_e=authority.rsa_key.e
)

# Submit complaint anonymously
submission = submission_handler.submit_complaint(
    complaint="This is my complaint about academic misconduct.",
    round_id="round_2024_01"
)

print(f"Submission created:")
print(f"  Complaint: {submission['complaint']}")
print(f"  Nullifier: {submission['nullifier']}")
print(f"  Round ID: {submission['round_id']}")
# Authority cannot link nullifier to user because it doesn't know the secret
```

### Verification Phase

```python
from implementation.verification import SubmissionVerifier, BulletinBoard

# Create verifier (anyone can do this with public parameters)
verifier = SubmissionVerifier(
    rsa_n=authority.rsa_key.n,
    rsa_e=authority.rsa_key.e,
    merkle_root=authority.merkle_tree.root
)

# Verify submission
results = verifier.verify_submission(submission)

print("Verification Results:")
print(f"  Proof valid: {results['proof_valid']}")
print(f"  Nullifier unique: {results['nullifier_unique']}")
print(f"  Complaint valid: {results['complaint_valid']}")
print(f"  Overall valid: {results['overall_valid']}")

if results['overall_valid']:
    # Add to bulletin board
    board = BulletinBoard(verifier)
    board_result = board.add_submission(submission)
    
    if board_result['overall_valid']:
        print("✓ Submission added to bulletin board")
        stats = board.get_statistics()
        print(f"  Total submissions: {stats['total_submissions']}")
    else:
        print("✗ Submission rejected")
```

### Batch Verification

Verify multiple submissions at once:

```python
# Submit multiple complaints
submissions = []
for i, (credential, secret) in enumerate(zip(credentials, secrets)):
    handler = ComplaintSubmission(credential, secret, rsa_n, rsa_e)
    submission = handler.submit_complaint(f"Complaint {i}", "round_2024_01")
    submissions.append(submission)

# Batch verify
results = verifier.verify_batch(submissions)
print(f"Total: {results['total']}, Valid: {results['valid']}, Invalid: {results['invalid']}")
```

## Complete Example

Here's a complete example showing all phases:

```python
from implementation.setup import AuthoritySetup
from implementation.registration import RegistrationProtocol
from implementation.submission import ComplaintSubmission
from implementation.verification import SubmissionVerifier, BulletinBoard
from Crypto.Random import get_random_bytes

# ===== SETUP PHASE =====
print("=== Setup Phase ===")
authority = AuthoritySetup(key_size=2048)
authority.generate_rsa_keys()

# Authority only knows public user IDs
user_ids = ['student1', 'student2', 'student3']
authority.add_authorized_users(user_ids)
authority.build_merkle_tree()

# ===== REGISTRATION PHASE =====
print("\n=== Registration Phase ===")
user_id = 'student1'
secret = get_random_bytes(32)  # User generates secret

merkle_path = authority.get_user_merkle_path(0)
merkle_root = authority.merkle_tree.root
rsa_n = authority.rsa_key.n
rsa_e = authority.rsa_key.e

credential = RegistrationProtocol.register_user(
    user_id, secret, merkle_path, merkle_root, rsa_n, rsa_e,
    authority.sign_blinded_token
)
print(f"✓ User '{user_id}' registered (authority doesn't know secret)")

# ===== SUBMISSION PHASE =====
print("\n=== Submission Phase ===")
submission_handler = ComplaintSubmission(credential, secret, rsa_n, rsa_e)
submission = submission_handler.submit_complaint(
    "This is a test complaint.",
    "round_2024_01"
)
print(f"✓ Complaint submitted (nullifier: {submission['nullifier'][:16]}...)")

# ===== VERIFICATION PHASE =====
print("\n=== Verification Phase ===")
verifier = SubmissionVerifier(rsa_n, rsa_e, merkle_root)
results = verifier.verify_submission(submission)

if results['overall_valid']:
    print("✓ Submission verified successfully")
    board = BulletinBoard(verifier)
    board.add_submission(submission)
    print(f"✓ Added to bulletin board")
else:
    print("✗ Submission verification failed")
```

## Key Points

### Anonymity Guarantees
- ✅ Authority never learns user secrets
- ✅ Merkle tree built from public IDs only
- ✅ Blind signatures prevent linking during registration
- ✅ Nullifiers cannot be linked to users (authority doesn't know secrets)

### Important Notes
1. **Secrets**: Users generate their own secrets. Authority never knows them.
2. **Credentials**: Do NOT contain secrets. Users must store secrets separately.
3. **Nullifiers**: Computed from secrets, so authority cannot link submissions.
4. **One-per-user**: Same user, same round → same nullifier (duplicates rejected).

## Common Patterns

### Multiple Users

```python
# Register multiple users
credentials = []
secrets = []
for i, user_id in enumerate(user_ids):
    secret = get_random_bytes(32)
    secrets.append(secret)
    merkle_path = authority.get_user_merkle_path(i)
    credential = RegistrationProtocol.register_user(
        user_id, secret, merkle_path, merkle_root, rsa_n, rsa_e,
        authority.sign_blinded_token
    )
    credentials.append(credential)
```

### Preventing Duplicates

```python
# Same user, same round → duplicate rejected
submission1 = handler.submit_complaint("First", "round_2024_01")
result1 = verifier.verify_submission(submission1)  # ✅ Valid

submission2 = handler.submit_complaint("Second", "round_2024_01")
result2 = verifier.verify_submission(submission2)  # ❌ Rejected (duplicate nullifier)

# Different round → allowed
submission3 = handler.submit_complaint("Third", "round_2024_02")
result3 = verifier.verify_submission(submission3)  # ✅ Valid
```

## Documentation

For more information, see:
- **README.md** - Installation and quick start
- **design_document.md** - Complete protocol specification
- **security_analysis/** - Threat model and security proofs

