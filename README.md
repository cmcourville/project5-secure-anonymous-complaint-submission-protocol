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

- Python 3.8+
- Required libraries: `pycryptodome`, `py-ecc`, `petlib`

### Installation

```bash
pip install -r requirements.txt
```

## Protocol Phases

1. **Setup Phase**: Authority generates keys and builds Merkle tree
2. **Registration Phase**: Users obtain anonymous credentials
3. **Submission Phase**: Users submit complaints with ZK-proofs
4. **Verification Phase**: Public verification of submissions

## Documentation

See `design_document.md` for complete protocol specification.

## License

Academic project for WPI CS 525/625.

