"""
Unit tests for Verification Phase.
"""

import pytest
from Crypto.Random import get_random_bytes
from implementation.setup import AuthoritySetup
from implementation.registration import RegistrationProtocol
from implementation.submission import ComplaintSubmission
from implementation.verification import SubmissionVerifier, BulletinBoard


class TestSubmissionVerifier:
    """Test submission verification."""
    
    @pytest.fixture
    def setup_complete(self):
        """Setup complete protocol for testing."""
        authority = AuthoritySetup(key_size=1024)
        authority.generate_rsa_keys()
        user_ids = ['student1', 'student2']
        authority.add_authorized_users(user_ids)
        authority.build_merkle_tree()
        
        # Register user
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
    
    def test_verify_valid_submission(self, setup_complete):
        """Test verifying a valid submission."""
        setup = setup_complete
        verifier = SubmissionVerifier(
            setup['rsa_n'], setup['rsa_e'], setup['merkle_root']
        )
        
        submission_handler = ComplaintSubmission(
            setup['credential'], setup['secret'], setup['rsa_n'], setup['rsa_e']
        )
        submission = submission_handler.submit_complaint("Test", "round_2024_01")
        
        results = verifier.verify_submission(submission)
        
        assert results['proof_valid'] is True
        assert results['nullifier_unique'] is True
        assert results['complaint_valid'] is True
        assert results['overall_valid'] is True
    
    def test_verify_nullifier_uniqueness(self, setup_complete):
        """Test that duplicate nullifiers are rejected."""
        setup = setup_complete
        verifier = SubmissionVerifier(
            setup['rsa_n'], setup['rsa_e'], setup['merkle_root']
        )
        
        submission_handler = ComplaintSubmission(
            setup['credential'], setup['secret'], setup['rsa_n'], setup['rsa_e']
        )
        
        round_id = "round_2024_01"
        submission1 = submission_handler.submit_complaint("Complaint 1", round_id)
        submission2 = submission_handler.submit_complaint("Complaint 2", round_id)
        
        # First submission should be valid
        results1 = verifier.verify_submission(submission1)
        assert results1['overall_valid'] is True
        
        # Second submission (same nullifier) should be rejected
        results2 = verifier.verify_submission(submission2)
        assert results2['nullifier_unique'] is False
        assert results2['overall_valid'] is False
    
    def test_verify_batch(self, setup_complete):
        """Test batch verification."""
        setup = setup_complete
        verifier = SubmissionVerifier(
            setup['rsa_n'], setup['rsa_e'], setup['merkle_root']
        )
        
        submission_handler = ComplaintSubmission(
            setup['credential'], setup['secret'], setup['rsa_n'], setup['rsa_e']
        )
        
        submissions = [
            submission_handler.submit_complaint("Complaint 1", "round_2024_01"),
            submission_handler.submit_complaint("Complaint 2", "round_2024_02"),
        ]
        
        results = verifier.verify_batch(submissions)
        
        assert results['total'] == 2
        assert results['valid'] == 2
        assert results['invalid'] == 0
    
    def test_verify_invalid_complaint_format(self, setup_complete):
        """Test that invalid complaint formats are rejected."""
        setup = setup_complete
        verifier = SubmissionVerifier(
            setup['rsa_n'], setup['rsa_e'], setup['merkle_root']
        )
        
        submission_handler = ComplaintSubmission(
            setup['credential'], setup['secret'], setup['rsa_n'], setup['rsa_e']
        )
        submission = submission_handler.submit_complaint("Valid", "round_2024_01")
        
        # Modify complaint to be invalid (too long)
        submission['complaint'] = 'x' * 10001  # Exceeds limit
        
        results = verifier.verify_submission(submission)
        assert results['complaint_valid'] is False
        assert results['overall_valid'] is False


class TestBulletinBoard:
    """Test bulletin board."""
    
    @pytest.fixture
    def setup_complete(self):
        """Setup complete protocol for testing."""
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
        
        verifier = SubmissionVerifier(rsa_n, rsa_e, merkle_root)
        
        return {
            'verifier': verifier,
            'credential': credential,
            'secret': secret,
            'rsa_n': rsa_n,
            'rsa_e': rsa_e
        }
    
    def test_add_valid_submission(self, setup_complete):
        """Test adding valid submission to bulletin board."""
        setup = setup_complete
        board = BulletinBoard(setup['verifier'])
        
        submission_handler = ComplaintSubmission(
            setup['credential'], setup['secret'], setup['rsa_n'], setup['rsa_e']
        )
        submission = submission_handler.submit_complaint("Test", "round_2024_01")
        
        result = board.add_submission(submission)
        
        assert result['overall_valid'] is True
        assert len(board.submissions) == 1
    
    def test_reject_invalid_submission(self, setup_complete):
        """Test that invalid submissions are rejected."""
        setup = setup_complete
        board = BulletinBoard(setup['verifier'])
        
        submission_handler = ComplaintSubmission(
            setup['credential'], setup['secret'], setup['rsa_n'], setup['rsa_e']
        )
        submission = submission_handler.submit_complaint("Test", "round_2024_01")
        
        # Add first submission
        board.add_submission(submission)
        
        # Try to add duplicate (should be rejected)
        duplicate = submission_handler.submit_complaint("Duplicate", "round_2024_01")
        result = board.add_submission(duplicate)
        
        assert result['overall_valid'] is False
        assert len(board.submissions) == 1  # Still only one submission
    
    def test_get_all_submissions(self, setup_complete):
        """Test getting all submissions from bulletin board."""
        setup = setup_complete
        board = BulletinBoard(setup['verifier'])
        
        submission_handler = ComplaintSubmission(
            setup['credential'], setup['secret'], setup['rsa_n'], setup['rsa_e']
        )
        
        submission1 = submission_handler.submit_complaint("Complaint 1", "round_2024_01")
        submission2 = submission_handler.submit_complaint("Complaint 2", "round_2024_02")
        
        board.add_submission(submission1)
        board.add_submission(submission2)
        
        all_submissions = board.get_all_submissions()
        
        assert len(all_submissions) == 2
    
    def test_verify_all_submissions(self, setup_complete):
        """Test re-verifying all submissions."""
        setup = setup_complete
        board = BulletinBoard(setup['verifier'])
        
        submission_handler = ComplaintSubmission(
            setup['credential'], setup['secret'], setup['rsa_n'], setup['rsa_e']
        )
        
        submission1 = submission_handler.submit_complaint("Complaint 1", "round_2024_01")
        submission2 = submission_handler.submit_complaint("Complaint 2", "round_2024_02")
        
        board.add_submission(submission1)
        board.add_submission(submission2)
        
        results = board.verify_all_submissions()
        
        assert results['total'] == 2
        assert results['valid'] == 2
    
    def test_get_statistics(self, setup_complete):
        """Test getting bulletin board statistics."""
        setup = setup_complete
        board = BulletinBoard(setup['verifier'])
        
        submission_handler = ComplaintSubmission(
            setup['credential'], setup['secret'], setup['rsa_n'], setup['rsa_e']
        )
        
        board.add_submission(submission_handler.submit_complaint("Test", "round_2024_01"))
        
        stats = board.get_statistics()
        
        assert stats['total_submissions'] == 1
        assert stats['unique_nullifiers'] == 1
        assert 'round_2024_01' in stats['rounds']

