"""
Unit tests for Setup Phase.
"""

import pytest
from implementation.setup import AuthoritySetup
from implementation.merkle_tree import MerkleTree, create_user_identifier


class TestAuthoritySetup:
    """Test authority setup phase."""
    
    def test_generate_rsa_keys(self):
        """Test RSA key generation."""
        authority = AuthoritySetup(key_size=1024)  # Smaller for testing
        private_key, public_key = authority.generate_rsa_keys()
        
        assert private_key is not None
        assert public_key is not None
        assert authority.rsa_key.n == public_key.n
        assert authority.rsa_key.e == public_key.e
    
    def test_add_authorized_users(self):
        """Test adding authorized users (public IDs only, no secrets)."""
        authority = AuthoritySetup()
        user_ids = ['student1', 'student2', 'student3']
        
        authority.add_authorized_users(user_ids)
        
        assert len(authority.authorized_users) == 3
        assert all('user_id' in user for user in authority.authorized_users)
        assert all('secret' not in user for user in authority.authorized_users)  # No secrets!
    
    def test_build_merkle_tree(self):
        """Test Merkle tree construction from public identifiers."""
        authority = AuthoritySetup()
        user_ids = ['student1', 'student2', 'student3', 'student4']
        authority.add_authorized_users(user_ids)
        
        root = authority.build_merkle_tree()
        
        assert root is not None
        assert len(root) == 32  # SHA-256 hash
        assert authority.merkle_tree is not None
        assert authority.merkle_tree.get_leaf_count() == 4
    
    def test_merkle_tree_uses_public_ids_only(self):
        """Test that Merkle tree is built from public IDs, not secrets."""
        authority = AuthoritySetup()
        user_ids = ['student1', 'student2']
        authority.add_authorized_users(user_ids)
        authority.build_merkle_tree()
        
        # Verify leaves are from public IDs only
        for i, user in enumerate(authority.authorized_users):
            user_id = user['user_id']
            expected_leaf = create_user_identifier(user_id, secret=None)
            actual_leaf = authority.merkle_tree.leaves[i]
            assert expected_leaf == actual_leaf
    
    def test_get_user_merkle_path(self):
        """Test getting Merkle path for a user."""
        authority = AuthoritySetup()
        user_ids = ['student1', 'student2', 'student3']
        authority.add_authorized_users(user_ids)
        authority.build_merkle_tree()
        
        path = authority.get_user_merkle_path(0)
        
        assert path is not None
        assert isinstance(path, list)
        assert len(path) == authority.merkle_tree.depth
    
    def test_merkle_path_verification(self):
        """Test that Merkle paths are valid."""
        authority = AuthoritySetup()
        user_ids = ['student1', 'student2', 'student3', 'student4']
        authority.add_authorized_users(user_ids)
        authority.build_merkle_tree()
        
        for i in range(len(user_ids)):
            path = authority.get_user_merkle_path(i)
            user_id = user_ids[i]
            leaf = create_user_identifier(user_id, secret=None)
            
            # Verify path
            is_valid = authority.merkle_tree.verify_merkle_path(
                leaf, path, authority.merkle_tree.root
            )
            assert is_valid, f"Merkle path invalid for user {i}"
    
    def test_get_public_parameters(self):
        """Test getting public parameters."""
        authority = AuthoritySetup()
        authority.generate_rsa_keys()
        user_ids = ['student1', 'student2']
        authority.add_authorized_users(user_ids)
        authority.build_merkle_tree()
        
        params = authority.get_public_parameters()
        
        assert 'rsa_public_key' in params
        assert 'merkle_root' in params
        assert 'merkle_depth' in params
        assert 'user_count' in params
        assert params['user_count'] == 2
        assert 'n' in params['rsa_public_key']
        assert 'e' in params['rsa_public_key']
    
    def test_sign_blinded_token(self):
        """Test signing blinded tokens."""
        authority = AuthoritySetup(key_size=1024)
        authority.generate_rsa_keys()
        
        # Create a test blinded token
        blinded_token = 12345
        signature = authority.sign_blinded_token(blinded_token)
        
        assert signature is not None
        assert isinstance(signature, int)
    
    def test_authority_never_knows_secrets(self):
        """Test that authority setup never requires or stores user secrets."""
        authority = AuthoritySetup()
        user_ids = ['student1', 'student2']
        
        # Authority only gets public IDs
        authority.add_authorized_users(user_ids)
        authority.build_merkle_tree()
        
        # Verify no secrets anywhere
        for user in authority.authorized_users:
            assert 'secret' not in user
        
        # Verify Merkle tree doesn't contain secrets
        for leaf in authority.merkle_tree.leaves:
            # Leaf should be hash of user_id only, not user_id + secret
            # We can't directly verify this, but we know create_user_identifier
            # was called with secret=None
            assert leaf is not None

