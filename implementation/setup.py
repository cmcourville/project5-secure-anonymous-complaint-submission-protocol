"""
Setup Phase: Authority generates keys and builds Merkle tree.

This module implements the setup phase where the authority:
1. Generates RSA key pair for blind signatures
2. Builds Merkle tree of authorized users
3. Publishes public parameters
"""

from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime
import hashlib
import json
from typing import List, Dict, Tuple
from .merkle_tree import MerkleTree, create_user_identifier


class AuthoritySetup:
    """Handles the setup phase of the protocol."""
    
    def __init__(self, key_size: int = 2048):
        """
        Initialize authority setup.
        
        Args:
            key_size: RSA key size in bits (default: 2048)
        """
        self.key_size = key_size
        self.rsa_key = None
        self.merkle_tree = None
        self.authorized_users = []
    
    def generate_rsa_keys(self) -> Tuple[RSA.RsaKey, RSA.RsaKey]:
        """
        Generate RSA key pair for blind signatures.
        
        Returns:
            Tuple of (private_key, public_key)
        """
        self.rsa_key = RSA.generate(self.key_size)
        return self.rsa_key, self.rsa_key.publickey()
    
    def add_authorized_users(self, user_ids: List[str]):
        """
        Add authorized users to the system.
        
        IMPORTANT: Authority only knows public user_ids, NOT secrets.
        Users will generate their own secrets during registration.
        
        Args:
            user_ids: List of public user identifiers (e.g., student IDs, usernames)
        """
        self.authorized_users = [{'user_id': uid} for uid in user_ids]
    
    def build_merkle_tree(self) -> bytes:
        """
        Build Merkle tree from authorized users.
        
        Returns:
            Merkle root hash
        """
        if not self.authorized_users:
            raise ValueError("No authorized users added")
        
        # Create leaf identifiers for each user
        # IMPORTANT: Use only public user_id, NOT secrets
        # Authority should never know user secrets
        leaves = []
        for user in self.authorized_users:
            user_id = user['user_id']
            # Build tree from public identifiers only
            leaf = create_user_identifier(user_id, secret=None)
            leaves.append(leaf)
        
        # Build Merkle tree
        self.merkle_tree = MerkleTree(leaves)
        return self.merkle_tree.root
    
    def get_public_parameters(self) -> Dict:
        """
        Get public parameters to publish.
        
        Returns:
            Dictionary containing public parameters
        """
        if not self.rsa_key or not self.merkle_tree:
            raise ValueError("Setup not complete. Generate keys and build tree first.")
        
        public_key = self.rsa_key.publickey()
        
        return {
            'rsa_public_key': {
                'n': public_key.n,
                'e': public_key.e
            },
            'merkle_root': self.merkle_tree.root.hex(),
            'merkle_depth': self.merkle_tree.depth,
            'user_count': len(self.authorized_users)
        }
    
    def get_user_merkle_path(self, user_index: int) -> List[Tuple[bytes, bool]]:
        """
        Get Merkle path for a specific user.
        
        Args:
            user_index: Index of user in authorized_users list
            
        Returns:
            Merkle path for the user
        """
        if not self.merkle_tree:
            raise ValueError("Merkle tree not built")
        
        return self.merkle_tree.get_merkle_path(user_index)
    
    def sign_blinded_token(self, blinded_token: int) -> int:
        """
        Sign a blinded token (authority doesn't see the actual token).
        
        Args:
            blinded_token: Blinded token value
            
        Returns:
            Signature on the blinded token
        """
        if not self.rsa_key:
            raise ValueError("RSA keys not generated")
        
        # Sign with private key: σ' = (m')^d mod n
        signature = pow(blinded_token, self.rsa_key.d, self.rsa_key.n)
        return signature
    
    def save_setup(self, filename: str):
        """Save setup parameters to file."""
        params = self.get_public_parameters()
        with open(filename, 'w') as f:
            json.dump(params, f, indent=2)
    
    @staticmethod
    def load_public_parameters(filename: str) -> Dict:
        """Load public parameters from file."""
        with open(filename, 'r') as f:
            return json.load(f)


def example_setup():
    """Example usage of setup phase."""
    # Initialize authority
    authority = AuthoritySetup()
    
    # Generate RSA keys
    private_key, public_key = authority.generate_rsa_keys()
    print(f"Generated RSA keys (size: {authority.key_size} bits)")
    
    # Add authorized users (authority only knows public IDs, not secrets)
    user_ids = ['student1', 'student2', 'student3', 'student4']
    authority.add_authorized_users(user_ids)
    
    # Build Merkle tree
    root = authority.build_merkle_tree()
    print(f"Merkle root: {root.hex()}")
    print(f"Tree depth: {authority.merkle_tree.depth}")
    
    # Get public parameters
    params = authority.get_public_parameters()
    print("\nPublic Parameters:")
    print(json.dumps(params, indent=2))
    
    return authority


if __name__ == '__main__':
    example_setup()

