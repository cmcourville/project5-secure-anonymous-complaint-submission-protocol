"""
Unit tests for Submission Phase.
"""

import pytest
from Crypto.Random import get_random_bytes
from implementation.setup import AuthoritySetup
from implementation.registration import RegistrationProtocol
from implementation.submission import (
    ComplaintSubmission, NullifierGenerator, ZKProofGenerator
)


class TestNullifierGenerator:
    """Test nullifier generation."""
    
    def test_generate_nullifier(self):
        """Test nullifier generation."""
        secret = get_random_bytes(32)
        round_id = "round_2024_01"
        
        nullifier = NullifierGenerator.generate_nullifier(secret, round_id)
        
        assert nullifier is not None
        assert isinstance(nullifier, str)
        assert len(nullifier) == 64  # SHA-256 hex string
    
    def test_nullifier_deterministic(self):
        """Test that nullifier is deterministic (same secret + round = same nullifier)."""
        secret = get_random_bytes(32)
        round_id = "round_2024_01"
        
        nullifier1 = NullifierGenerator.generate_nullifier(secret, round_id)
        nullifier2 = NullifierGenerator.generate_nullifier(secret, round_id)
        
        assert nullifier1 == nullifier2
    
    def test_nullifier_different_for_different_secrets(self):
        """Test that different secrets produce different nullifiers."""
        secret1 = get_random_bytes(32)
        secret2 = get_random_bytes(32)
        round_id = "round_2024_01"
        
        nullifier1 = NullifierGenerator.generate_nullifier(secret1, round_id)
        nullifier2 = NullifierGenerator.generate_nullifier(secret2, round_id)
        
        assert nullifier1 != nullifier2
    
    def test_nullifier_different_for_different_rounds(self):
        """Test that different rounds produce different nullifiers."""
        secret = get_random_bytes(32)
        round_id1 = "round_2024_01"
        round_id2 = "round_2024_02"
        
        nullifier1 = NullifierGenerator.generate_nullifier(secret, round_id1)
        nullifier2 = NullifierGenerator.generate_nullifier(secret, round_id2)
        
        assert nullifier1 != nullifier2


class TestComplaintSubmission:
    """Test complaint submission."""
    
    @pytest.fixture
    def setup_and_registration(self):
        """Setup authority and register a user."""
        authority = AuthoritySetup(key_size=1024)
        authority.generate_rsa_keys()
        user_ids = ['student1']
        authority.add_authorized_users(user_ids)
        authority.build_merkle_tree()
        
        user_id = 'student1'
        secret = get_random_bytes(32)
        merkle_path = authority.get_user_merkle_path(0)
        merkle_root = authority.merkle_tree.root
        rsa_n = authority.rsa_key.n
        rsa_e = authority.rsa_key.e
        
        credential = RegistrationProtocol.register_user(
            user_id, secret, merkle_path, merkle_root, rsa_n, rsa_e,
            authority.sign_blinded_token
        )
        
        return {
            'authority': authority,
            'credential': credential,
            'secret': secret,
            'user_id': user_id,
            'rsa_n': rsa_n,
            'rsa_e': rsa_e,
            'merkle_root': merkle_root
        }
    
    def test_submit_complaint(self, setup_and_registration):
        """Test submitting a complaint."""
        setup = setup_and_registration
        submission_handler = ComplaintSubmission(
            setup['credential'], setup['secret'], setup['rsa_n'], setup['rsa_e']
        )
        
        complaint = "This is a test complaint."
        round_id = "round_2024_01"
        
        submission = submission_handler.submit_complaint(complaint, round_id)
        
        assert 'complaint' in submission
        assert 'round_id' in submission
        assert 'nullifier' in submission
        assert 'proof' in submission
        assert submission['complaint'] == complaint
        assert submission['round_id'] == round_id
    
    def test_nullifier_in_submission(self, setup_and_registration):
        """Test that nullifier is included in submission."""
        setup = setup_and_registration
        submission_handler = ComplaintSubmission(
            setup['credential'], setup['secret'], setup['rsa_n'], setup['rsa_e']
        )
        
        complaint = "Test complaint"
        round_id = "round_2024_01"
        submission = submission_handler.submit_complaint(complaint, round_id)
        
        # Verify nullifier is correct
        expected_nullifier = NullifierGenerator.generate_nullifier(
            setup['secret'], round_id
        )
        assert submission['nullifier'] == expected_nullifier
    
    def test_same_user_same_round_same_nullifier(self, setup_and_registration):
        """Test that same user, same round produces same nullifier (one-per-user)."""
        setup = setup_and_registration
        submission_handler = ComplaintSubmission(
            setup['credential'], setup['secret'], setup['rsa_n'], setup['rsa_e']
        )
        
        round_id = "round_2024_01"
        submission1 = submission_handler.submit_complaint("Complaint 1", round_id)
        submission2 = submission_handler.submit_complaint("Complaint 2", round_id)
        
        # Same user, same round → same nullifier
        assert submission1['nullifier'] == submission2['nullifier']
    
    def test_different_rounds_different_nullifiers(self, setup_and_registration):
        """Test that different rounds produce different nullifiers."""
        setup = setup_and_registration
        submission_handler = ComplaintSubmission(
            setup['credential'], setup['secret'], setup['rsa_n'], setup['rsa_e']
        )
        
        submission1 = submission_handler.submit_complaint("Complaint", "round_2024_01")
        submission2 = submission_handler.submit_complaint("Complaint", "round_2024_02")
        
        # Different rounds → different nullifiers
        assert submission1['nullifier'] != submission2['nullifier']
    
    def test_zk_proof_in_submission(self, setup_and_registration):
        """Test that ZK-proof is included in submission."""
        setup = setup_and_registration
        submission_handler = ComplaintSubmission(
            setup['credential'], setup['secret'], setup['rsa_n'], setup['rsa_e']
        )
        
        submission = submission_handler.submit_complaint("Test", "round_2024_01")
        
        assert 'proof' in submission
        proof = submission['proof']
        assert 'sig_commitment' in proof
        assert 'path_commitment' in proof
        assert 'challenge' in proof
        assert 'response' in proof
        assert 'merkle_root' in proof
    
    def test_secret_required_for_submission(self, setup_and_registration):
        """Test that secret is required for submission (not in credential)."""
        setup = setup_and_registration
        
        # Credential should not contain secret
        assert 'secret' not in setup['credential']
        
        # Submission requires secret parameter
        submission_handler = ComplaintSubmission(
            setup['credential'], setup['secret'], setup['rsa_n'], setup['rsa_e']
        )
        
        # Should work with secret
        submission = submission_handler.submit_complaint("Test", "round_2024_01")
        assert submission is not None

