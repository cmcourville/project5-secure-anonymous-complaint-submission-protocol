"""
Implementation package for Secure Anonymous Complaint Submission Protocol.

This package contains:
- setup.py: Authority setup and key generation
- registration.py: User registration and credential issuance
- submission.py: Complaint submission with ZK-proofs
- verification.py: Public verification of submissions
- merkle_tree.py: Merkle tree implementation for membership proofs
"""

from .setup import AuthoritySetup
from .registration import UserRegistration, RegistrationProtocol
from .submission import ComplaintSubmission, NullifierGenerator, ZKProofGenerator
from .verification import SubmissionVerifier, BulletinBoard
from .merkle_tree import MerkleTree, create_user_identifier

__all__ = [
    'AuthoritySetup',
    'UserRegistration',
    'RegistrationProtocol',
    'ComplaintSubmission',
    'NullifierGenerator',
    'ZKProofGenerator',
    'SubmissionVerifier',
    'BulletinBoard',
    'MerkleTree',
    'create_user_identifier'
]

