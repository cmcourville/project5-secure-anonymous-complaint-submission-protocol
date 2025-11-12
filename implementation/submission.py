"""
Submission Phase: Users submit complaints with ZK-proofs.

This module implements the submission phase where users:
1. Create nullifier to prevent double submissions
2. Generate ZK-proof of credential validity
3. Submit complaint anonymously
"""

import hashlib
from typing import Dict, List, Tuple
from Crypto.Util.number import getRandomRange


class NullifierGenerator:
    """Generates nullifiers to prevent double submissions."""
    
    @staticmethod
    def generate_nullifier(secret: bytes, round_id: str) -> str:
        """
        Generate nullifier for a submission round.
        
        Args:
            secret: User's secret value
            round_id: Identifier for the submission round
            
        Returns:
            Nullifier hash (hex string)
        """
        data = secret + round_id.encode()
        nullifier = hashlib.sha256(data).digest()
        return nullifier.hex()


class ZKProofGenerator:
    """
    Simplified ZK-proof generator.
    
    Note: This is a simplified implementation. A full zk-SNARK implementation
    would require circuit compilation (e.g., using Circom) and proof generation
    (e.g., using snarkjs). This demonstrates the concept.
    """
    
    def __init__(self, signature: int, secret: bytes, user_id: str, 
                 merkle_path: List[Tuple[bytes, bool]], merkle_root: bytes,
                 rsa_n: int, rsa_e: int):
        """
        Initialize ZK-proof generator.
        
        Args:
            signature: User's credential signature
            secret: User's secret
            user_id: User identifier
            merkle_path: Merkle path
            merkle_root: Merkle root
            rsa_n: RSA modulus
            rsa_e: RSA exponent
        """
        self.signature = signature
        self.secret = secret
        self.user_id = user_id
        self.merkle_path = merkle_path
        self.merkle_root = merkle_root
        self.rsa_n = rsa_n
        self.rsa_e = rsa_e
    
    def _hash(self, data: bytes) -> bytes:
        """Hash function."""
        return hashlib.sha256(data).digest()
    
    def generate_proof(self, nullifier: str) -> Dict:
        """
        Generate ZK-proof of credential validity.
        
        In a full implementation, this would use zk-SNARKs to prove:
        - "I know (signature, secret, merkle_path) such that:
            - signature is valid RSA signature on H(secret || user_id)
            - merkle_path is valid path to merkle_root
            - nullifier = H(secret || round_id)"
        
        This simplified version creates a commitment-based proof.
        
        Args:
            nullifier: The nullifier for this submission
            
        Returns:
            Proof dictionary
        """
        # Create commitments (simplified ZK-proof)
        # In real implementation, this would be a proper zk-SNARK proof
        
        # Commit to signature
        sig_commitment = hashlib.sha256(
            str(self.signature).encode() + self.secret
        ).hex()
        
        # Commit to Merkle path
        path_commitment = hashlib.sha256(
            str(self.merkle_path).encode() + self.secret
        ).hex()
        
        # Create challenge (in interactive proof, this would be from verifier)
        challenge = hashlib.sha256(
            sig_commitment.encode() + path_commitment.encode() + nullifier.encode()
        ).digest()
        
        # Create response (simplified)
        response = hashlib.sha256(
            challenge + self.secret
        ).hex()
        
        return {
            'sig_commitment': sig_commitment,
            'path_commitment': path_commitment,
            'challenge': challenge.hex(),
            'response': response,
            'merkle_root': self.merkle_root.hex()
        }
    
    def verify_proof_structure(self, proof: Dict, nullifier: str) -> bool:
        """
        Verify proof structure (simplified verification).
        
        In full implementation, this would verify the zk-SNARK proof.
        
        Args:
            proof: The proof to verify
            nullifier: Expected nullifier
            
        Returns:
            True if proof structure is valid
        """
        # Verify commitments are present
        required_fields = ['sig_commitment', 'path_commitment', 'challenge', 'response', 'merkle_root']
        if not all(field in proof for field in required_fields):
            return False
        
        # Verify challenge matches
        expected_challenge = hashlib.sha256(
            proof['sig_commitment'].encode() + 
            proof['path_commitment'].encode() + 
            nullifier.encode()
        ).digest()
        
        return proof['challenge'] == expected_challenge.hex()


class ComplaintSubmission:
    """Handles complaint submission."""
    
    def __init__(self, credential: Dict, rsa_n: int, rsa_e: int):
        """
        Initialize complaint submission.
        
        Args:
            credential: User's credential from registration
            rsa_n: RSA modulus (public)
            rsa_e: RSA exponent (public)
        """
        self.credential = credential
        self.rsa_n = rsa_n
        self.rsa_e = rsa_e
    
    def submit_complaint(self, complaint_text: str, round_id: str) -> Dict:
        """
        Submit a complaint anonymously.
        
        Args:
            complaint_text: The complaint content
            round_id: Identifier for the submission round
            
        Returns:
            Submission dictionary
        """
        # Extract credential components
        signature = self.credential['signature']
        merkle_path = self.credential['merkle_path']
        merkle_root = bytes.fromhex(self.credential['merkle_root'])
        
        # Note: In real implementation, we'd need secret and user_id
        # For this simplified version, we'll use the stored hash
        # In practice, these would be stored securely by the user
        
        # Generate nullifier
        # Note: This requires the secret, which should be stored securely
        # For demonstration, we'll create a placeholder
        secret = b'user_secret'  # In practice, retrieved from secure storage
        nullifier = NullifierGenerator.generate_nullifier(secret, round_id)
        
        # Generate ZK-proof
        # Note: Full implementation would use proper zk-SNARKs
        zk_proof_gen = ZKProofGenerator(
            signature, secret, 'user', merkle_path, merkle_root, self.rsa_n, self.rsa_e
        )
        proof = zk_proof_gen.generate_proof(nullifier)
        
        # Create submission
        submission = {
            'complaint': complaint_text,
            'round_id': round_id,
            'nullifier': nullifier,
            'proof': proof,
            'timestamp': None  # Could add timestamp if needed
        }
        
        return submission


def example_submission():
    """Example usage of submission phase."""
    from .setup import AuthoritySetup
    from .registration import RegistrationProtocol
    
    # Setup
    authority = AuthoritySetup()
    authority.generate_rsa_keys()
    users = [{'user_id': 'student1', 'secret': b'secret1'}]
    authority.add_authorized_users(users)
    authority.build_merkle_tree()
    
    # Registration
    user_id = 'student1'
    secret = b'secret1'
    merkle_path = authority.get_user_merkle_path(0)
    merkle_root = authority.merkle_tree.root
    rsa_n = authority.rsa_key.n
    rsa_e = authority.rsa_key.e
    
    credential = RegistrationProtocol.register_user(
        user_id, secret, merkle_path, merkle_root, rsa_n, rsa_e,
        authority.sign_blinded_token
    )
    
    # Submission
    submission_handler = ComplaintSubmission(credential, rsa_n, rsa_e)
    complaint = "This is a test complaint about academic misconduct."
    round_id = "round_2024_01"
    
    submission = submission_handler.submit_complaint(complaint, round_id)
    
    print("Submission created:")
    print(f"Complaint: {submission['complaint']}")
    print(f"Nullifier: {submission['nullifier']}")
    print(f"Proof: {submission['proof']}")
    
    return submission


if __name__ == '__main__':
    example_submission()

