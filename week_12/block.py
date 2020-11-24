from dataclasses import dataclass
from typing import List, Dict

from Crypto.Hash import SHA256
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


class Address:
    def __init__(self, pk: bytes):
        k = SHA256.new(pk)
        self.__address = k.hexdigest()

    def __bytes__(self):
        return bytes.fromhex(self.__address)

    def __str__(self):
        return f'0x{self.__address}'


@dataclass
class Transaction:
    sender: Address            # sender's address
    receiver: Address          # receiver's address
    value: int                 # amount the sender send to receiver
    nonce: bytes               # random value for checking double spending
    signature: bytes or None   # Signature

    def hash(self) -> SHA256Hash:
        k = SHA256.new()
        k.update(bytes(self.sender))
        k.update(bytes(self.receiver))
        k.update(bytes(self.value))
        k.update(bytes(self.nonce))
        return k

    def sign(self, sk: ECC):
        signer = DSS.new(sk, 'fips-186-3')
        hash_val = self.hash()
        self.signature = signer.sign(hash_val)


@dataclass
class MerkleNode:
    hash: bytes
    left: 'MerkleNode' or None
    right: 'MerkleNode' or None

    def __init__(self, left: 'MerkleNode' or None = None, right: 'MerkleNode' or None = None, hash_val: bytes = None):
        if hash_val:
            self.hash = hash_val
            self.left = None
            self.right = None
        else:
            k = SHA256.new()
            if left:
                k.update(left.hash)
                self.left = left
            if right:
                k.update(right.hash)
                self.right = right
            self.hash = bytes.fromhex(k.hexdigest())


class MerkleTree:
    def __init__(self, transaction_list: List[Transaction]):
        merkle_nodes = list(map(
            lambda transaction: MerkleNode(hash_val=bytes(transaction.hash().digest())),
            transaction_list,
        ))
        self.root = self.make_merkle_tree(merkle_nodes)

    @classmethod
    def make_merkle_tree(self, merkle_nodes: List[MerkleNode]) -> MerkleNode:
        """
        TODO: merkle tree를 만드는 함수
        최종 반환 시에는 Merkle root를 반환함
        :param merkle_nodes: Merkle Node list to be Merkle Tree
        :return: Root node of merkle tree
        """

        node_count = len(merkle_nodes)

        # return node if there's only one merkle node exists
        if node_count == 1:
            return merkle_nodes[0]
        
        new_node_list = []

        # creates new merkle root two by two
        for i in range(0, node_count, 2):
            # last one should be stored into new list as is
            if i + 1 == node_count:
                new_node_list.append(merkle_nodes[i])
            # create new root node for current and next node
            else:
                new_node_list.append(
                    MerkleNode(merkle_nodes[i], merkle_nodes[i+1])
                )
        
        return self.make_merkle_tree(new_node_list)
        

    def merkle_root(self) -> bytes:
        return self.root.hash


@dataclass
class BlockHeader:
    block_number: int   # number of block
    parent_hash: bytes  # parent block's hash
    merkle_root: bytes  # root of merkle tree
    state_root: bytes   # root of state tree
    difficulty: int     # block difficulty
    nonce: int          # random value


@dataclass
class State:
    address: Address    # address
    value: int          # amount of address


@dataclass
class Block:
    block_header: BlockHeader
    merkle_tree: MerkleTree
    state_tree: Dict[Address, int]
