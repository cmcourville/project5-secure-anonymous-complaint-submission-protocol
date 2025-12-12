"""
Test script for the complete protocol flow.

This script demonstrates the full protocol from setup to verification.
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from implementation.setup import AuthoritySetup
from implementation.registration import RegistrationProtocol
from implementation.submission import ComplaintSubmission
from implementation.verification import SubmissionVerifier, BulletinBoard


def test_complete_protocol():
    """Test the complete protocol flow."""
    print("=" * 60)
    print("Secure Anonymous Complaint Submission Protocol - Test")
    print("=" * 60)
    
    # Setup Phase
    print("\n[1] SETUP PHASE")
    print("-" * 60)
    authority = AuthoritySetup(key_size=2048)
    private_key, public_key = authority.generate_rsa_keys()
    print("✓ Generated RSA keys (2048 bits)")
    
    # Add authorized users (authority only knows public IDs, NOT secrets)
    user_ids = ['student1', 'student2', 'student3']
    authority.add_authorized_users(user_ids)
    print(f"✓ Added {len(user_ids)} authorized users")
    
    # User Commitment Phase (fixes ZK-proof binding issue)
    print("\n[1a] USER COMMITMENT PHASE")
    print("-" * 60)
    from implementation.merkle_tree import create_user_identifier
    user_secrets = {}
    commitments = []
    for user_id in user_ids:
        secret = get_random_bytes(32)
        commitment = create_user_identifier(user_id, secret)
        user_secrets[user_id] = secret
        commitments.append(commitment)
        print(f"✓ User '{user_id}' generated commitment (secret unknown to authority)")
    
    # Collect commitments and build tree with bindings
    authority.collect_user_commitments(commitments)
    root = authority.build_merkle_tree(use_commitments=True)
    print(f"✓ Built Merkle tree from commitments (root: {root.hex()[:16]}...)")
    print("  Note: Tree uses H(user_id || secret) to bind proof components")
    
    # Get public parameters
    params = authority.get_public_parameters()
    print("✓ Public parameters generated")
    
    # Registration Phase
    print("\n[2] REGISTRATION PHASE")
    print("-" * 60)
    from Crypto.Random import get_random_bytes
    
    user_id = 'student1'
    # Use the secret from commitment phase (authority never learned this)
    secret = user_secrets[user_id]
    merkle_path = authority.get_user_merkle_path(0)
    merkle_root = authority.merkle_tree.root
    rsa_n = authority.rsa_key.n
    rsa_e = authority.rsa_key.e
    
    credential = RegistrationProtocol.register_user(
        user_id, secret, merkle_path, merkle_root, rsa_n, rsa_e,
        authority.sign_blinded_token
    )
    print(f"✓ User '{user_id}' registered successfully")
    print(f"  Credential signature: {credential['signature']}")
    print(f"  Note: User secret is NOT known to authority")
    
    # Submission Phase
    print("\n[3] SUBMISSION PHASE")
    print("-" * 60)
    # User provides secret separately (stored securely by user)
    submission_handler = ComplaintSubmission(credential, secret, rsa_n, rsa_e)
    complaint = "This is a test complaint about academic misconduct."
    round_id = "round_2024_01"
    
    submission = submission_handler.submit_complaint(complaint, round_id)
    print(f"✓ Complaint submitted successfully")
    print(f"  Complaint: {complaint[:50]}...")
    print(f"  Nullifier: {submission['nullifier'][:16]}...")
    print(f"  Round ID: {round_id}")
    print(f"  Note: Authority cannot link nullifier to user (doesn't know secret)")
    
    # Verification Phase
    print("\n[4] VERIFICATION PHASE")
    print("-" * 60)
    verifier = SubmissionVerifier(rsa_n, rsa_e, merkle_root)
    results = verifier.verify_submission(submission)
    
    print("Verification Results:")
    print(f"  Proof valid: {results['proof_valid']}")
    print(f"  Nullifier unique: {results['nullifier_unique']}")
    print(f"  Complaint valid: {results['complaint_valid']}")
    print(f"  Overall valid: {results['overall_valid']}")
    
    if results['overall_valid']:
        print("✓ Submission verified successfully")
    else:
        print("✗ Submission verification failed")
        return False
    
    # Bulletin Board
    print("\n[5] BULLETIN BOARD")
    print("-" * 60)
    # Create fresh verifier for bulletin board (or board will reuse same nullifier set)
    board_verifier = SubmissionVerifier(rsa_n, rsa_e, merkle_root)
    board = BulletinBoard(board_verifier)
    board_result = board.add_submission(submission)
    
    if board_result['overall_valid']:
        print("✓ Submission added to bulletin board")
    else:
        print("✗ Submission rejected by bulletin board")
        return False
    
    stats = board.get_statistics()
    print(f"  Total submissions: {stats['total_submissions']}")
    print(f"  Unique nullifiers: {stats['unique_nullifiers']}")
    
    # Test duplicate prevention
    print("\n[6] DUPLICATE PREVENTION TEST")
    print("-" * 60)
    # Same user, same round, same secret → same nullifier (duplicate)
    duplicate_submission = submission_handler.submit_complaint(
        "Duplicate complaint", round_id
    )
    # Use board verifier to check duplicate (it already has the first nullifier)
    duplicate_results = board_verifier.verify_submission(duplicate_submission)
    
    if not duplicate_results['nullifier_unique']:
        print("✓ Duplicate submission correctly rejected")
    else:
        print("✗ Duplicate submission incorrectly accepted")
        return False
    
    print("\n" + "=" * 60)
    print("ALL TESTS PASSED!")
    print("=" * 60)
    return True


if __name__ == '__main__':
    try:
        success = test_complete_protocol()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

