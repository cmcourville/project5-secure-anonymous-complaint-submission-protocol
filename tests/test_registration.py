"""
Unit tests for Registration Phase.
"""

import pytest
from Crypto.Random import get_random_bytes
from implementation.setup import AuthoritySetup
from implementation.registration import UserRegistration, RegistrationProtocol
from implementation.merkle_tree import create_user_identifier


class TestUserRegistration:
    """Test user registration phase."""
    
    @pytest.fixture
    def authority_setup(self):
        """Create authority setup for testing with commitment-based tree."""
        from tests.conftest import setup_authority_with_commitments
        user_ids = ['student1', 'student2', 'student3']
        authority, user_secrets = setup_authority_with_commitments(user_ids, key_size=1024)
        # Store user secrets in authority for test access
        authority._test_user_secrets = user_secrets
        return authority
    
    def test_user_generates_secret(self):
        """Test that users generate their own secrets."""
        # User generates secret (authority never knows this)
        secret = get_random_bytes(32)
        
        assert secret is not None
        assert len(secret) == 32
        # Secret should be random (very unlikely to be all zeros)
        assert secret != b'\x00' * 32
    
    def test_user_registration_initialization(self, authority_setup):
        """Test user registration initialization."""
        user_id = 'student1'
        # Use the secret from the commitment-based setup
        secret = authority_setup._test_user_secrets[user_id]['secret']
        merkle_path = authority_setup.get_user_merkle_path(0)
        merkle_root = authority_setup.merkle_tree.root
        rsa_n = authority_setup.rsa_key.n
        rsa_e = authority_setup.rsa_key.e
        
        user_reg = UserRegistration(
            user_id, secret, merkle_path, merkle_root, rsa_n, rsa_e
        )
        
        assert user_reg.user_id == user_id
        assert user_reg.secret == secret
        assert user_reg.merkle_path == merkle_path
    
    def test_merkle_path_verification(self, authority_setup):
        """Test that user can verify their Merkle path."""
        user_id = 'student1'
        # Use the secret from the commitment-based setup
        secret = authority_setup._test_user_secrets[user_id]['secret']
        merkle_path = authority_setup.get_user_merkle_path(0)
        merkle_root = authority_setup.merkle_tree.root
        rsa_n = authority_setup.rsa_key.n
        rsa_e = authority_setup.rsa_key.e
        
        user_reg = UserRegistration(
            user_id, secret, merkle_path, merkle_root, rsa_n, rsa_e
        )
        
        # Path should be valid (verified in __init__)
        assert user_reg.public_leaf is not None
        assert user_reg.user_commitment is not None
    
    def test_create_blinded_token(self, authority_setup):
        """Test creating blinded token."""
        user_id = 'student1'
        # Use the secret from the commitment-based setup
        secret = authority_setup._test_user_secrets[user_id]['secret']
        merkle_path = authority_setup.get_user_merkle_path(0)
        merkle_root = authority_setup.merkle_tree.root
        rsa_n = authority_setup.rsa_key.n
        rsa_e = authority_setup.rsa_key.e
        
        user_reg = UserRegistration(
            user_id, secret, merkle_path, merkle_root, rsa_n, rsa_e
        )
        
        blinded_token, r = user_reg.create_blinded_token()
        
        assert blinded_token is not None
        assert r is not None
        assert isinstance(blinded_token, int)
        assert isinstance(r, int)
    
    def test_unblind_signature(self, authority_setup):
        """Test unblinding signature."""
        user_id = 'student1'
        # Use the secret from the commitment-based setup
        secret = authority_setup._test_user_secrets[user_id]['secret']
        merkle_path = authority_setup.get_user_merkle_path(0)
        merkle_root = authority_setup.merkle_tree.root
        rsa_n = authority_setup.rsa_key.n
        rsa_e = authority_setup.rsa_key.e
        
        user_reg = UserRegistration(
            user_id, secret, merkle_path, merkle_root, rsa_n, rsa_e
        )
        
        blinded_token, r = user_reg.create_blinded_token()
        blinded_signature = authority_setup.sign_blinded_token(blinded_token)
        signature = user_reg.unblind_signature(blinded_signature, r)
        
        assert signature is not None
        assert isinstance(signature, int)
    
    def test_verify_credential(self, authority_setup):
        """Test credential verification."""
        user_id = 'student1'
        # Use the secret from the commitment-based setup
        secret = authority_setup._test_user_secrets[user_id]['secret']
        merkle_path = authority_setup.get_user_merkle_path(0)
        merkle_root = authority_setup.merkle_tree.root
        rsa_n = authority_setup.rsa_key.n
        rsa_e = authority_setup.rsa_key.e
        
        user_reg = UserRegistration(
            user_id, secret, merkle_path, merkle_root, rsa_n, rsa_e
        )
        
        blinded_token, r = user_reg.create_blinded_token()
        blinded_signature = authority_setup.sign_blinded_token(blinded_token)
        signature = user_reg.unblind_signature(blinded_signature, r)
        
        is_valid = user_reg.verify_credential(signature)
        assert is_valid
    
    def test_complete_registration_protocol(self, authority_setup):
        """Test complete registration protocol."""
        user_id = 'student1'
        # Use the secret from the commitment-based setup
        secret = authority_setup._test_user_secrets[user_id]['secret']
        merkle_path = authority_setup.get_user_merkle_path(0)
        merkle_root = authority_setup.merkle_tree.root
        rsa_n = authority_setup.rsa_key.n
        rsa_e = authority_setup.rsa_key.e
        
        credential = RegistrationProtocol.register_user(
            user_id, secret, merkle_path, merkle_root, rsa_n, rsa_e,
            authority_setup.sign_blinded_token
        )
        
        assert 'signature' in credential
        assert 'merkle_path' in credential
        assert 'merkle_root' in credential
        assert 'user_id' in credential
        assert 'secret' not in credential  # Secret NOT in credential!
    
    def test_authority_never_learns_secret(self, authority_setup):
        """Test that authority never learns user secret during registration."""
        user_id = 'student1'
        # Use the secret from the commitment-based setup
        secret = authority_setup._test_user_secrets[user_id]['secret']
        merkle_path = authority_setup.get_user_merkle_path(0)
        merkle_root = authority_setup.merkle_tree.root
        rsa_n = authority_setup.rsa_key.n
        rsa_e = authority_setup.rsa_key.e
        
        # Register user
        credential = RegistrationProtocol.register_user(
            user_id, secret, merkle_path, merkle_root, rsa_n, rsa_e,
            authority_setup.sign_blinded_token
        )
        
        # Verify secret is not in credential
        assert 'secret' not in credential
        
        # Verify authority doesn't have access to secret
        # (In real implementation, authority would have no way to access it)
        # We can't directly test this, but we verify the credential structure
    
    def test_different_users_different_credentials(self, authority_setup):
        """Test that different users get different credentials."""
        user1_id = 'student1'
        user2_id = 'student2'
        # Use the secrets from the commitment-based setup
        secret1 = authority_setup._test_user_secrets[user1_id]['secret']
        secret2 = authority_setup._test_user_secrets[user2_id]['secret']
        
        merkle_path1 = authority_setup.get_user_merkle_path(0)
        merkle_path2 = authority_setup.get_user_merkle_path(1)
        merkle_root = authority_setup.merkle_tree.root
        rsa_n = authority_setup.rsa_key.n
        rsa_e = authority_setup.rsa_key.e
        
        credential1 = RegistrationProtocol.register_user(
            user1_id, secret1, merkle_path1, merkle_root, rsa_n, rsa_e,
            authority_setup.sign_blinded_token
        )
        
        credential2 = RegistrationProtocol.register_user(
            user2_id, secret2, merkle_path2, merkle_root, rsa_n, rsa_e,
            authority_setup.sign_blinded_token
        )
        
        # Credentials should be different
        assert credential1['signature'] != credential2['signature']
    
    def test_invalid_merkle_path_rejected(self, authority_setup):
        """Test that invalid Merkle paths are rejected."""
        user_id = 'student1'
        # Use the secret from the commitment-based setup
        secret = authority_setup._test_user_secrets[user_id]['secret']
        # Use wrong Merkle path (for different user)
        wrong_merkle_path = authority_setup.get_user_merkle_path(1)
        merkle_root = authority_setup.merkle_tree.root
        rsa_n = authority_setup.rsa_key.n
        rsa_e = authority_setup.rsa_key.e
        
        # This should raise an error because path doesn't match user_id + secret commitment
        with pytest.raises(ValueError, match="Invalid Merkle path"):
            UserRegistration(
                user_id, secret, wrong_merkle_path, merkle_root, rsa_n, rsa_e
            )

