# Unit Tests

This directory contains comprehensive unit tests to verify all security requirements are met.

## Running Tests

### Run all tests
```bash
pytest tests/
```

### Run with coverage
```bash
pytest tests/ --cov=implementation --cov-report=html
```

### Run specific test file
```bash
pytest tests/test_requirements.py
```

### Run specific test class
```bash
pytest tests/test_requirements.py::TestAnonymity
```

### Run with verbose output
```bash
pytest tests/ -v
```

## Test Structure

### `test_setup.py`
Tests for Setup Phase:
- RSA key generation
- Merkle tree construction
- Public parameter generation
- Authority never knows user secrets

### `test_registration.py`
Tests for Registration Phase:
- User secret generation
- Blind signature protocol
- Credential issuance
- Authority never learns secrets

### `test_submission.py`
Tests for Submission Phase:
- Nullifier generation
- ZK-proof creation
- Complaint submission
- One-per-user enforcement

### `test_verification.py`
Tests for Verification Phase:
- Submission verification
- Nullifier uniqueness checking
- Bulletin board operations
- Batch verification

### `test_requirements.py`
**Critical tests verifying all security requirements:**
- **Anonymity**: Authority cannot link submissions to users
- **Authentication**: Only authorized users can submit
- **One-per-user**: Each user submits at most one per round
- **Verifiability**: Public verification of all submissions

## Test Coverage

The tests verify:

1. ✅ **Anonymity**
   - Authority never learns user secrets
   - Authority cannot link nullifiers to users
   - Submissions cannot be linked to specific users

2. ✅ **Authentication**
   - Authorized users can submit
   - Unauthorized users cannot submit valid complaints

3. ✅ **One-per-user**
   - Same user, same round → same nullifier
   - Duplicate submissions are rejected
   - Different rounds allow different submissions

4. ✅ **Verifiability**
   - Public verification works
   - All valid submissions are included
   - Invalid submissions are rejected

## Expected Results

All tests should pass, confirming that:
- The protocol correctly implements all security requirements
- Anonymity is preserved (authority never knows secrets)
- Authentication works (only authorized users)
- One-per-user is enforced (nullifiers prevent duplicates)
- Verifiability is public (anyone can verify)

