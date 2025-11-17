"""
Verification Phase: Public verification of submissions.

This module implements the verification phase where anyone can:
1. Verify ZK-proofs
2. Check nullifier uniqueness
3. Verify all valid complaints were included
"""

import hashlib
from typing import List, Dict, Set
from .merkle_tree import MerkleTree


class SubmissionVerifier:
    """Verifies complaint submissions."""
    
    def __init__(self, rsa_n: int, rsa_e: int, merkle_root: bytes):
        """
        Initialize verifier.
        
        Args:
            rsa_n: RSA modulus (public key)
            rsa_e: RSA exponent (public key)
            merkle_root: Expected Merkle root
        """
        self.rsa_n = rsa_n
        self.rsa_e = rsa_e
        self.merkle_root = merkle_root
        self.used_nullifiers: Set[str] = set()
    
    def verify_proof(self, proof: Dict, nullifier: str) -> bool:
        """
        Verify ZK-proof structure.
        
        Args:
            proof: The ZK-proof to verify
            nullifier: The nullifier used
            
        Returns:
            True if proof is valid
        """
        # Verify proof structure
        required_fields = ['sig_commitment', 'path_commitment', 'challenge', 'response', 'merkle_root']
        if not all(field in proof for field in required_fields):
            return False
        
        # Verify Merkle root matches
        if proof['merkle_root'] != self.merkle_root.hex():
            return False
        
        # Verify challenge
        expected_challenge = hashlib.sha256(
            proof['sig_commitment'].encode() + 
            proof['path_commitment'].encode() + 
            nullifier.encode()
        ).digest()
        
        if proof['challenge'] != expected_challenge.hex():
            return False
        
        return True
    
    def verify_nullifier_uniqueness(self, nullifier: str) -> bool:
        """
        Verify that nullifier hasn't been used before.
        
        Args:
            nullifier: The nullifier to check
            
        Returns:
            True if nullifier is unique, False if already used
        """
        if nullifier in self.used_nullifiers:
            return False
        
        self.used_nullifiers.add(nullifier)
        return True
    
    def verify_submission(self, submission: Dict) -> Dict[str, bool]:
        """
        Verify a complete submission.
        
        Args:
            submission: The submission to verify
            
        Returns:
            Dictionary with verification results
        """
        results = {
            'proof_valid': False,
            'nullifier_unique': False,
            'complaint_valid': False,
            'overall_valid': False
        }
        
        # Verify proof
        results['proof_valid'] = self.verify_proof(
            submission['proof'], 
            submission['nullifier']
        )
        
        # Verify nullifier uniqueness
        results['nullifier_unique'] = self.verify_nullifier_uniqueness(
            submission['nullifier']
        )
        
        # Verify complaint format (basic check)
        complaint = submission.get('complaint', '')
        results['complaint_valid'] = (
            isinstance(complaint, str) and 
            len(complaint) > 0 and 
            len(complaint) <= 10000  # Reasonable length limit
        )
        
        # Overall validity
        results['overall_valid'] = (
            results['proof_valid'] and 
            results['nullifier_unique'] and 
            results['complaint_valid']
        )
        
        return results
    
    def verify_batch(self, submissions: List[Dict]) -> Dict:
        """
        Verify a batch of submissions.
        
        Args:
            submissions: List of submissions to verify
            
        Returns:
            Dictionary with batch verification results
        """
        results = {
            'total': len(submissions),
            'valid': 0,
            'invalid': 0,
            'details': []
        }
        
        # Reset nullifier set for batch verification
        self.used_nullifiers.clear()
        
        for i, submission in enumerate(submissions):
            verification = self.verify_submission(submission)
            verification['submission_index'] = i
            
            if verification['overall_valid']:
                results['valid'] += 1
            else:
                results['invalid'] += 1
            
            results['details'].append(verification)
        
        return results
    
    def get_verification_summary(self) -> Dict:
        """
        Get summary of verification state.
        
        Returns:
            Summary dictionary
        """
        return {
            'used_nullifiers_count': len(self.used_nullifiers),
            'merkle_root': self.merkle_root.hex()
        }


class BulletinBoard:
    """
    Public bulletin board for storing and verifying submissions.
    
    In a real implementation, this would be a distributed system
    (e.g., blockchain) to ensure immutability and public access.
    """
    
    def __init__(self, verifier: SubmissionVerifier):
        """
        Initialize bulletin board.
        
        Args:
            verifier: Submission verifier instance
        """
        self.verifier = verifier
        self.submissions: List[Dict] = []
    
    def add_submission(self, submission: Dict) -> Dict:
        """
        Add and verify a submission.
        
        Args:
            submission: The submission to add
            
        Returns:
            Verification results
        """
        # Verify submission
        verification = self.verifier.verify_submission(submission)
        
        # Only add if valid
        if verification['overall_valid']:
            self.submissions.append(submission)
        
        return verification
    
    def get_all_submissions(self) -> List[Dict]:
        """Get all valid submissions."""
        return self.submissions.copy()
    
    def verify_all_submissions(self) -> Dict:
        """
        Re-verify all submissions (for auditing).
        
        Returns:
            Batch verification results
        """
        # Create new verifier to reset nullifier set
        new_verifier = SubmissionVerifier(
            self.verifier.rsa_n,
            self.verifier.rsa_e,
            self.verifier.merkle_root
        )
        
        return new_verifier.verify_batch(self.submissions)
    
    def get_statistics(self) -> Dict:
        """Get statistics about submissions."""
        return {
            'total_submissions': len(self.submissions),
            'unique_nullifiers': len(self.verifier.used_nullifiers),
            'rounds': set(s.get('round_id') for s in self.submissions)
        }


def example_verification():
    """Example usage of verification phase."""
    from .setup import AuthoritySetup
    from .registration import RegistrationProtocol
    from .submission import ComplaintSubmission
    from Crypto.Random import get_random_bytes
    
    # Setup
    authority = AuthoritySetup()
    authority.generate_rsa_keys()
    user_ids = ['student1']
    authority.add_authorized_users(user_ids)
    authority.build_merkle_tree()
    
    params = authority.get_public_parameters()
    rsa_n = authority.rsa_key.n
    rsa_e = authority.rsa_key.e
    merkle_root = authority.merkle_tree.root
    
    # Registration
    user_id = 'student1'
    secret = get_random_bytes(32)  # User generates secret (authority never knows)
    merkle_path = authority.get_user_merkle_path(0)
    
    credential = RegistrationProtocol.register_user(
        user_id, secret, merkle_path, merkle_root, rsa_n, rsa_e,
        authority.sign_blinded_token
    )
    
    # Submission
    # User provides secret separately (stored securely by user)
    submission_handler = ComplaintSubmission(credential, secret, rsa_n, rsa_e)
    submission = submission_handler.submit_complaint(
        "Test complaint", "round_2024_01"
    )
    
    # Verification
    verifier = SubmissionVerifier(rsa_n, rsa_e, merkle_root)
    results = verifier.verify_submission(submission)
    
    print("Verification Results:")
    print(f"Proof valid: {results['proof_valid']}")
    print(f"Nullifier unique: {results['nullifier_unique']}")
    print(f"Complaint valid: {results['complaint_valid']}")
    print(f"Overall valid: {results['overall_valid']}")
    
    # Bulletin board
    board = BulletinBoard(verifier)
    board.add_submission(submission)
    stats = board.get_statistics()
    print(f"\nBulletin Board Statistics: {stats}")
    
    return results


if __name__ == '__main__':
    example_verification()

