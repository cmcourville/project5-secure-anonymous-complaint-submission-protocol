# Secure Anonymous Complaint Submission Protocol

## Project Overview

This project implements a hybrid cryptographic protocol combining **Zero-Knowledge Proofs** and **Blind Signatures** to enable secure, anonymous complaint submission with the following properties:

- **Anonymity**: No party can link a complaint to a specific user
- **Authentication**: Only authorized users can submit complaints
- **One-per-user**: Each user can submit exactly one complaint per round
- **Verifiability**: Anyone can verify all valid complaints were included

## Protocol Approach

**Hybrid: ZK-Proofs + Blind Signatures**

This approach combines:
- **Blind Signatures**: For anonymous credential issuance during registration
- **Zero-Knowledge Proofs**: For efficient membership proofs and nullifier verification
- **Merkle Trees**: For efficient authorization set representation
- **Nullifiers**: For preventing double submissions

## Project Structure

```
.
├── README.md
├── design_document.md          # Comprehensive protocol design document
├── implementation/             # Protocol implementation code
│   ├── setup.py               # Setup phase implementation
│   ├── registration.py        # Registration phase
│   ├── submission.py          # Submission phase
│   ├── verification.py        # Verification phase
│   └── merkle_tree.py         # Merkle tree utilities
├── diagrams/                   # Protocol flow diagrams
│   ├── protocol_flow.png
│   └── security_model.png
├── presentation/               # Presentation materials
│   ├── slides.md
│   └── presentation_notes.md
├── security_analysis/          # Security analysis documents
│   ├── threat_model.md
│   └── security_proofs.md
└── final_report.md            # Final project report
```

## Getting Started

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Installation

1. Clone or navigate to the project directory:
```bash
cd project5-secure-anonymous-complaint-submission-protocol
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

This will install:
- `pycryptodome` - Cryptographic primitives
- `pytest` - Testing framework
- Other required dependencies

## How to Run

### Quick Start: Run Complete Protocol Demo

Run the complete protocol flow (all phases):

```bash
python implementation/test_protocol.py
```

This demonstrates:
- ✅ Setup: Authority generates keys and builds Merkle tree
- ✅ Registration: User registers and obtains credential
- ✅ Submission: User submits complaint anonymously
- ✅ Verification: Public verification of submission
- ✅ Duplicate Prevention: Second submission rejected

**Expected Output:**
```
============================================================
Secure Anonymous Complaint Submission Protocol - Test
============================================================

[1] SETUP PHASE
------------------------------------------------------------
✓ Generated RSA keys (2048 bits)
✓ Added 3 authorized users
✓ Built Merkle tree (root: ...)
✓ Public parameters generated

[2] REGISTRATION PHASE
------------------------------------------------------------
✓ User 'student1' registered successfully
  Credential signature: ...
  Note: User secret is NOT known to authority

[3] SUBMISSION PHASE
------------------------------------------------------------
✓ Complaint submitted successfully
  Complaint: This is a test complaint about academic misconduct.
  Nullifier: ...
  Round ID: round_2024_01
  Note: Authority cannot link nullifier to user (doesn't know secret)

[4] VERIFICATION PHASE
------------------------------------------------------------
Verification Results:
  Proof valid: True
  Nullifier unique: True
  Complaint valid: True
  Overall valid: True
✓ Submission verified successfully

[5] BULLETIN BOARD
------------------------------------------------------------
✓ Submission added to bulletin board
  Total submissions: 1
  Unique nullifiers: 1

[6] DUPLICATE PREVENTION TEST
------------------------------------------------------------
✓ Duplicate submission correctly rejected

============================================================
ALL TESTS PASSED!
============================================================
```

### Run Unit Tests

Run all unit tests to verify requirements:

```bash
# Run all tests
pytest tests/

# Run with verbose output
pytest tests/ -v

# Run specific test file
pytest tests/test_requirements.py -v

# Run with coverage report
pytest tests/ --cov=implementation --cov-report=html
```

### Run Individual Phase Examples

Test each phase separately:

```bash
# Setup phase
python -c "from implementation.setup import example_setup; example_setup()"

# Registration phase
python -c "from implementation.registration import example_registration; example_registration()"

# Submission phase
python -c "from implementation.submission import example_submission; example_submission()"

# Verification phase
python -c "from implementation.verification import example_verification; example_verification()"
```

## Protocol Phases

1. **Setup Phase**: Authority generates keys and builds Merkle tree
2. **Registration Phase**: Users obtain anonymous credentials
3. **Submission Phase**: Users submit complaints with ZK-proofs
4. **Verification Phase**: Public verification of submissions

## Using the Protocol in Your Code

See `USAGE.md` for detailed code examples showing how to use each phase of the protocol programmatically.

## Testing Requirements

The test suite verifies all security requirements:

- ✅ **Anonymity**: Authority cannot link submissions to users
- ✅ **Authentication**: Only authorized users can submit
- ✅ **One-per-user**: Each user submits at most one per round
- ✅ **Verifiability**: Public verification works correctly

Run tests:
```bash
pytest tests/test_requirements.py -v
```

## Documentation

- **Design Document**: `design_document.md` - Complete protocol specification
- **Security Analysis**: `security_analysis/` - Threat model and security proofs
- **Final Report**: `final_report.md` - Project summary and analysis
- **Presentation**: `presentation/` - Slides and presentation notes
- **Usage Guide**: `USAGE.md` - Detailed code examples

## Troubleshooting

### Import Errors

If you get import errors, make sure you're running from the project root:

```bash
cd /path/to/project5-secure-anonymous-complaint-submission-protocol
python implementation/test_protocol.py
```

### Missing Dependencies

If dependencies are missing:

```bash
pip install -r requirements.txt
```

### RSA Key Generation is Slow

For faster testing, use smaller keys (not recommended for production):

```python
authority = AuthoritySetup(key_size=1024)  # Smaller for testing
```

**Note**: Use 2048+ bits for production!

### Python Version Issues

Make sure you're using Python 3.8 or higher:

```bash
python --version  # Should show 3.8+
```

If you have multiple Python versions, use:
```bash
python3 implementation/test_protocol.py
```

## Project Structure

```
.
├── README.md                    # This file
├── requirements.txt             # Python dependencies
├── design_document.md          # Complete protocol design
├── final_report.md             # Final project report
├── USAGE.md                    # Detailed usage guide
├── implementation/             # Protocol implementation
│   ├── setup.py               # Setup phase
│   ├── registration.py        # Registration phase
│   ├── submission.py          # Submission phase
│   ├── verification.py        # Verification phase
│   ├── merkle_tree.py         # Merkle tree utilities
│   └── test_protocol.py       # Complete protocol test
├── tests/                      # Unit tests
│   ├── test_setup.py
│   ├── test_registration.py
│   ├── test_submission.py
│   ├── test_verification.py
│   ├── test_requirements.py  # Requirements verification
│   └── test_completeness.py
├── security_analysis/          # Security documentation
│   ├── threat_model.md
│   └── security_proofs.md
├── presentation/               # Presentation materials
│   ├── slides.md
│   └── presentation_notes.md
└── diagrams/                   # Protocol diagrams
    ├── protocol_flow.txt
    └── security_model.txt
```

## License

Academic project for WPI CS 525/625 - Cryptography.

