"""
Tests to verify completeness of verifiability requirement.

Ensures that:
- All valid complaints are included
- No invalid complaints are injected
"""

import pytest
from Crypto.Random import get_random_bytes
from implementation.setup import AuthoritySetup
from implementation.registration import RegistrationProtocol
from implementation.submission import ComplaintSubmission
from implementation.verification import SubmissionVerifier, BulletinBoard


class TestCompleteness:
    """Test that all valid complaints are included and no invalid ones are injected."""
    
    @pytest.fixture
    def setup_multiple_users(self):
        """Setup with multiple authorized users."""
        authority = AuthoritySetup(key_size=1024)
        authority.generate_rsa_keys()
        user_ids = ['student1', 'student2', 'student3']
        authority.add_authorized_users(user_ids)
        authority.build_merkle_tree()
        
        # Register all users
        credentials = []
        secrets = []
        for i, user_id in enumerate(user_ids):
            secret = get_random_bytes(32)
            secrets.append(secret)
            merkle_path = authority.get_user_merkle_path(i)
            merkle_root = authority.merkle_tree.root
            rsa_n = authority.rsa_key.n
            rsa_e = authority.rsa_key.e
            
            credential = RegistrationProtocol.register_user(
                user_id, secret, merkle_path, merkle_root, rsa_n, rsa_e,
                authority.sign_blinded_token
            )
            credentials.append(credential)
        
        return {
            'authority': authority,
            'credentials': credentials,
            'secrets': secrets,
            'user_ids': user_ids,
            'rsa_n': authority.rsa_key.n,
            'rsa_e': authority.rsa_key.e,
            'merkle_root': authority.merkle_tree.root
        }
    
    def test_all_valid_submissions_included(self, setup_multiple_users):
        """Test that all valid submissions are included in verification."""
        setup = setup_multiple_users
        verifier = SubmissionVerifier(
            setup['rsa_n'], setup['rsa_e'], setup['merkle_root']
        )
        
        # All users submit complaints
        submissions = []
        for credential, secret in zip(setup['credentials'], setup['secrets']):
            submission_handler = ComplaintSubmission(
                credential, secret, setup['rsa_n'], setup['rsa_e']
            )
            submission = submission_handler.submit_complaint(
                f"Complaint from user", "round_2024_01"
            )
            submissions.append(submission)
        
        # Verify all submissions
        results = verifier.verify_batch(submissions)
        
        # All should be valid
        assert results['total'] == len(setup['user_ids'])
        assert results['valid'] == len(setup['user_ids'])
        assert results['invalid'] == 0
        
        # All should be included
        for detail in results['details']:
            assert detail['overall_valid'] is True
    
    def test_invalid_submissions_rejected(self, setup_multiple_users):
        """Test that invalid submissions are rejected."""
        setup = setup_multiple_users
        verifier = SubmissionVerifier(
            setup['rsa_n'], setup['rsa_e'], setup['merkle_root']
        )
        
        # Create valid submission
        credential = setup['credentials'][0]
        secret = setup['secrets'][0]
        submission_handler = ComplaintSubmission(
            credential, secret, setup['rsa_n'], setup['rsa_e']
        )
        valid_submission = submission_handler.submit_complaint("Valid", "round_2024_01")
        
        # Create invalid submissions
        invalid_submissions = []
        
        # Invalid 1: Corrupted proof
        invalid1 = valid_submission.copy()
        invalid1['proof']['challenge'] = 'corrupted_challenge'
        invalid_submissions.append(invalid1)
        
        # Invalid 2: Wrong Merkle root
        invalid2 = valid_submission.copy()
        invalid2['proof']['merkle_root'] = 'wrong_root'
        invalid_submissions.append(invalid2)
        
        # Invalid 3: Empty complaint
        invalid3 = valid_submission.copy()
        invalid3['complaint'] = ''
        invalid_submissions.append(invalid3)
        
        # Invalid 4: Missing required fields
        invalid4 = valid_submission.copy()
        del invalid4['proof']
        invalid_submissions.append(invalid4)
        
        # Verify all invalid submissions are rejected
        for invalid_submission in invalid_submissions:
            results = verifier.verify_submission(invalid_submission)
            assert results['overall_valid'] is False
    
    def test_bulletin_board_only_includes_valid(self, setup_multiple_users):
        """Test that bulletin board only includes valid submissions."""
        setup = setup_multiple_users
        verifier = SubmissionVerifier(
            setup['rsa_n'], setup['rsa_e'], setup['merkle_root']
        )
        board = BulletinBoard(verifier)
        
        # Submit valid complaints
        valid_submissions = []
        for credential, secret in zip(setup['credentials'], setup['secrets']):
            submission_handler = ComplaintSubmission(
                credential, secret, setup['rsa_n'], setup['rsa_e']
            )
            submission = submission_handler.submit_complaint(
                "Valid complaint", "round_2024_01"
            )
            valid_submissions.append(submission)
        
        # Add valid submissions
        for submission in valid_submissions:
            result = board.add_submission(submission)
            assert result['overall_valid'] is True
        
        # Try to add invalid submission
        import copy
        invalid = copy.deepcopy(valid_submissions[0])
        invalid['proof']['challenge'] = 'corrupted'
        result = board.add_submission(invalid)
        assert result['overall_valid'] is False
        
        # Bulletin board should only have valid submissions
        all_submissions = board.get_all_submissions()
        assert len(all_submissions) == len(valid_submissions)
        
        # All should be valid
        verification = board.verify_all_submissions()
        assert verification['valid'] == len(valid_submissions)
        assert verification['invalid'] == 0
    
    def test_no_duplicate_nullifiers_accepted(self, setup_multiple_users):
        """Test that duplicate nullifiers are not accepted."""
        setup = setup_multiple_users
        verifier = SubmissionVerifier(
            setup['rsa_n'], setup['rsa_e'], setup['merkle_root']
        )
        board = BulletinBoard(verifier)
        
        # Submit first complaint
        credential = setup['credentials'][0]
        secret = setup['secrets'][0]
        submission_handler = ComplaintSubmission(
            credential, secret, setup['rsa_n'], setup['rsa_e']
        )
        submission1 = submission_handler.submit_complaint("First", "round_2024_01")
        
        # Add first submission
        result1 = board.add_submission(submission1)
        assert result1['overall_valid'] is True
        
        # Try to submit duplicate (same user, same round)
        submission2 = submission_handler.submit_complaint("Duplicate", "round_2024_01")
        result2 = board.add_submission(submission2)
        assert result2['overall_valid'] is False
        assert result2['nullifier_unique'] is False
        
        # Bulletin board should still only have one submission
        assert len(board.submissions) == 1
    
    def test_verification_ensures_completeness(self, setup_multiple_users):
        """Test that verification ensures all valid submissions are included."""
        setup = setup_multiple_users
        verifier = SubmissionVerifier(
            setup['rsa_n'], setup['rsa_e'], setup['merkle_root']
        )
        board = BulletinBoard(verifier)
        
        # Submit all valid complaints
        all_submissions = []
        for credential, secret in zip(setup['credentials'], setup['secrets']):
            submission_handler = ComplaintSubmission(
                credential, secret, setup['rsa_n'], setup['rsa_e']
            )
            submission = submission_handler.submit_complaint(
                "Complaint", "round_2024_01"
            )
            all_submissions.append(submission)
            board.add_submission(submission)
        
        # Verify all are included
        assert len(board.submissions) == len(setup['user_ids'])
        
        # Re-verify all submissions
        verification = board.verify_all_submissions()
        assert verification['total'] == len(setup['user_ids'])
        assert verification['valid'] == len(setup['user_ids'])
        assert verification['invalid'] == 0
        
        # All submissions should be valid
        for detail in verification['details']:
            assert detail['overall_valid'] is True

