"""
Merkle Tree implementation for efficient membership proofs.

The Merkle tree stores authorized users and allows users to prove
membership without revealing their position in the tree.
"""

import hashlib
from typing import List, Tuple, Optional


class MerkleTree:
    """Binary Merkle tree for membership proofs."""
    
    def __init__(self, leaves: List[bytes]):
        """
        Initialize Merkle tree from list of leaf values.
        
        Args:
            leaves: List of leaf values (user identifiers)
        """
        if not leaves:
            raise ValueError("Merkle tree requires at least one leaf")
        
        self.leaves = leaves
        self.tree = self._build_tree(leaves)
        self.root = self.tree[-1][0] if self.tree else None
        self.depth = len(self.tree) - 1
    
    def _hash(self, data: bytes) -> bytes:
        """Hash function for Merkle tree nodes."""
        return hashlib.sha256(data).digest()
    
    def _build_tree(self, leaves: List[bytes]) -> List[List[bytes]]:
        """Build Merkle tree bottom-up."""
        tree = [leaves.copy()]
        current_level = leaves
        
        while len(current_level) > 1:
            next_level = []
            # Pair up nodes and hash
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    # Two children
                    combined = current_level[i] + current_level[i + 1]
                    next_level.append(self._hash(combined))
                else:
                    # Odd node, hash with itself
                    combined = current_level[i] + current_level[i]
                    next_level.append(self._hash(combined))
            tree.append(next_level)
            current_level = next_level
        
        return tree
    
    def get_merkle_path(self, leaf_index: int) -> List[Tuple[bytes, bool]]:
        """
        Get Merkle path for a leaf node.
        
        Args:
            leaf_index: Index of the leaf in the original leaves list
            
        Returns:
            List of (sibling_hash, is_right) tuples representing the path
        """
        if leaf_index < 0 or leaf_index >= len(self.leaves):
            raise ValueError("Invalid leaf index")
        
        path = []
        current_index = leaf_index
        
        for level in range(self.depth):
            level_nodes = self.tree[level]
            sibling_index = current_index ^ 1  # XOR to get sibling
            
            if sibling_index < len(level_nodes):
                sibling_hash = level_nodes[sibling_index]
                is_right = (current_index % 2) == 0
                path.append((sibling_hash, is_right))
            else:
                # No sibling, use node itself
                node_hash = level_nodes[current_index]
                path.append((node_hash, False))
            
            current_index = current_index // 2
        
        return path
    
    def verify_merkle_path(
        self, 
        leaf: bytes, 
        path: List[Tuple[bytes, bool]], 
        root: bytes
    ) -> bool:
        """
        Verify a Merkle path.
        
        Args:
            leaf: The leaf value (already a hash from create_user_identifier)
            path: List of (sibling_hash, is_right) tuples
            root: Expected root hash
            
        Returns:
            True if path is valid, False otherwise
        """
        # Leaf is already a hash (from create_user_identifier), use it directly
        # The Merkle tree stores leaves as-is and hashes them when building parent nodes
        current_hash = leaf
        
        for sibling_hash, is_right in path:
            if is_right:
                # Current is left, sibling is right
                combined = current_hash + sibling_hash
            else:
                # Current is right, sibling is left
                combined = sibling_hash + current_hash
            
            current_hash = self._hash(combined)
        
        return current_hash == root
    
    def get_leaf_count(self) -> int:
        """Get number of leaves in the tree."""
        return len(self.leaves)


def create_user_identifier(user_id: str, secret: bytes = None) -> bytes:
    """
    Create a unique identifier for a user in the Merkle tree.
    
    For public Merkle tree (authority knows), use only user_id.
    For user commitment (user knows secret), use user_id + secret.
    
    Args:
        user_id: Public user identifier
        secret: User's secret value (optional, for commitment)
        
    Returns:
        Hash of user_id (and secret if provided)
    """
    if secret is None:
        # Public identifier (authority knows this)
        return hashlib.sha256(user_id.encode()).digest()
    else:
        # User commitment (authority doesn't know secret)
        combined = user_id.encode() + secret
        return hashlib.sha256(combined).digest()

