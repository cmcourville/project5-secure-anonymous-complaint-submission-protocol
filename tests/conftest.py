"""
Pytest configuration and shared fixtures.
"""

import pytest
import sys
import os
from Crypto.Random import get_random_bytes

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from implementation.setup import AuthoritySetup
from implementation.merkle_tree import create_user_identifier


def setup_authority_with_commitments(user_ids, key_size=1024):
    """
    Helper function to set up authority with commitment-based Merkle tree.
    
    This fixes the ZK-proof binding issue by building the tree from
    H(user_id || secret) instead of H(user_id).
    
    Args:
        user_ids: List of user identifiers
        key_size: RSA key size in bits
        
    Returns:
        Tuple of (authority, user_secrets_dict) where user_secrets_dict
        maps user_id to (secret, commitment, merkle_path_index)
    """
    authority = AuthoritySetup(key_size=key_size)
    authority.generate_rsa_keys()
    authority.add_authorized_users(user_ids)
    
    # Generate secrets and commitments for each user
    user_secrets = {}
    commitments = []
    
    for i, user_id in enumerate(user_ids):
        secret = get_random_bytes(32)
        commitment = create_user_identifier(user_id, secret)
        user_secrets[user_id] = {
            'secret': secret,
            'commitment': commitment,
            'index': i
        }
        commitments.append(commitment)
    
    # Collect commitments and build tree
    authority.collect_user_commitments(commitments)
    authority.build_merkle_tree(use_commitments=True)
    
    return authority, user_secrets

