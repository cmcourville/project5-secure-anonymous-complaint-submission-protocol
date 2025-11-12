"""
Registration Phase: Users obtain anonymous credentials.

This module implements the registration phase where users:
1. Prove Merkle tree membership (without revealing position)
2. Receive blind signature on their credential
3. Unblind to get anonymous credential
"""

from Crypto.Util.number import getRandomRange
from Crypto.Random import get_random_bytes
import hashlib
from typing import List, Tuple, Dict
from .merkle_tree import MerkleTree, create_user_identifier


class UserRegistration:
    """Handles user registration and credential issuance."""
    
    def __init__(self, user_id: str, secret: bytes, merkle_path: List[Tuple[bytes, bool]], 
                 merkle_root: bytes, rsa_n: int, rsa_e: int):
        """
        Initialize user registration.
        
        Args:
            user_id: User's identifier
            secret: User's secret value
            merkle_path: Merkle path proving membership
            merkle_root: Root of the Merkle tree
            rsa_n: RSA modulus (public key)
            rsa_e: RSA public exponent
        """
        self.user_id = user_id
        self.secret = secret
        self.merkle_path = merkle_path
        self.merkle_root = merkle_root
        self.rsa_n = rsa_n
        self.rsa_e = rsa_e
        
        # Create user identifier for Merkle tree
        self.leaf = create_user_identifier(user_id, secret)
        
        # Verify Merkle path
        if not self._verify_merkle_path():
            raise ValueError("Invalid Merkle path")
    
    def _hash(self, data: bytes) -> bytes:
        """Hash function matching Merkle tree."""
        return hashlib.sha256(data).digest()
    
    def _verify_merkle_path(self) -> bool:
        """Verify that Merkle path is valid."""
        current_hash = self._hash(self.leaf)
        
        for sibling_hash, is_right in self.merkle_path:
            if is_right:
                combined = current_hash + sibling_hash
            else:
                combined = sibling_hash + current_hash
            current_hash = self._hash(combined)
        
        return current_hash == self.merkle_root
    
    def create_blinded_token(self) -> Tuple[int, int]:
        """
        Create blinded token for blind signature.
        
        Returns:
            Tuple of (blinded_token, blinding_factor)
        """
        # Create token: H(secret || user_id)
        token_data = self.secret + self.user_id.encode()
        token_hash = int.from_bytes(self._hash(token_data), 'big')
        token = token_hash % self.rsa_n
        
        # Generate random blinding factor
        r = getRandomRange(2, self.rsa_n - 1)
        
        # Blind token: m' = m · r^e mod n
        blinded_token = (token * pow(r, self.rsa_e, self.rsa_n)) % self.rsa_n
        
        return blinded_token, r
    
    def unblind_signature(self, blinded_signature: int, blinding_factor: int) -> int:
        """
        Unblind the signature received from authority.
        
        Args:
            blinded_signature: Signature on blinded token
            blinding_factor: The blinding factor used
            
        Returns:
            Unblinded signature on original token
        """
        # Unblind: σ = σ' · r^(-1) mod n
        r_inv = pow(blinding_factor, -1, self.rsa_n)
        signature = (blinded_signature * r_inv) % self.rsa_n
        
        return signature
    
    def verify_credential(self, signature: int) -> bool:
        """
        Verify that the credential (signature) is valid.
        
        Args:
            signature: The unblinded signature
            
        Returns:
            True if signature is valid, False otherwise
        """
        # Recreate token
        token_data = self.secret + self.user_id.encode()
        token_hash = int.from_bytes(self._hash(token_data), 'big')
        token = token_hash % self.rsa_n
        
        # Verify signature: token == signature^e mod n
        verified_token = pow(signature, self.rsa_e, self.rsa_n)
        
        return verified_token == token
    
    def get_credential(self) -> Dict:
        """
        Get user's credential (to be stored securely).
        
        Returns:
            Dictionary containing credential components
        """
        # Create blinded token
        blinded_token, r = self.create_blinded_token()
        
        # In real protocol, this would be sent to authority
        # For now, we'll simulate the authority signing
        # (In actual implementation, authority.sign_blinded_token would be called)
        
        return {
            'user_id': self.user_id,
            'merkle_path': [(h.hex(), is_right) for h, is_right in self.merkle_path],
            'merkle_root': self.merkle_root.hex(),
            'blinding_factor': r,
            'blinded_token': blinded_token
        }


class RegistrationProtocol:
    """Complete registration protocol between user and authority."""
    
    @staticmethod
    def register_user(
        user_id: str,
        secret: bytes,
        merkle_path: List[Tuple[bytes, bool]],
        merkle_root: bytes,
        rsa_n: int,
        rsa_e: int,
        authority_signer
    ) -> Dict:
        """
        Complete registration protocol.
        
        Args:
            user_id: User identifier
            secret: User secret
            merkle_path: Merkle path from authority
            merkle_root: Merkle root
            rsa_n: RSA modulus
            rsa_e: RSA exponent
            authority_signer: Function that signs blinded tokens
            
        Returns:
            User's credential
        """
        # User creates registration request
        user_reg = UserRegistration(user_id, secret, merkle_path, merkle_root, rsa_n, rsa_e)
        
        # User blinds token
        blinded_token, r = user_reg.create_blinded_token()
        
        # Authority signs blinded token (without seeing actual token)
        blinded_signature = authority_signer(blinded_token)
        
        # User unblinds signature
        signature = user_reg.unblind_signature(blinded_signature, r)
        
        # User verifies credential
        if not user_reg.verify_credential(signature):
            raise ValueError("Invalid credential received")
        
        # Return credential
        return {
            'signature': signature,
            'merkle_path': merkle_path,
            'merkle_root': merkle_root.hex(),
            'user_id_hash': hashlib.sha256(user_id.encode() + secret).digest().hex()
        }


def example_registration():
    """Example usage of registration phase."""
    # Simulate authority setup
    from .setup import AuthoritySetup
    
    authority = AuthoritySetup()
    authority.generate_rsa_keys()
    
    users = [
        {'user_id': 'student1', 'secret': b'secret1'},
        {'user_id': 'student2', 'secret': b'secret2'},
    ]
    authority.add_authorized_users(users)
    authority.build_merkle_tree()
    
    # User registration
    user_id = 'student1'
    secret = b'secret1'
    merkle_path = authority.get_user_merkle_path(0)
    merkle_root = authority.merkle_tree.root
    rsa_n = authority.rsa_key.n
    rsa_e = authority.rsa_key.e
    
    # Register user
    credential = RegistrationProtocol.register_user(
        user_id, secret, merkle_path, merkle_root, rsa_n, rsa_e,
        authority.sign_blinded_token
    )
    
    print("Registration successful!")
    print(f"Credential signature: {credential['signature']}")
    
    return credential


if __name__ == '__main__':
    example_registration()

