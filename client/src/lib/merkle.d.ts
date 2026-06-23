export interface MerkleProof {
  pathElements: bigint[];
  pathIndices: number[];
}

export interface NonMembershipProof {
  lower_leaf: bigint;
  upper_leaf: bigint;
  lower_path: bigint[];
  lower_idx: number[];
  upper_path: bigint[];
  upper_idx: number[];
}

export class MerkleTree {
  depth: number;
  leaves: bigint[];
  tree: bigint[][];
  zeroHashes: bigint[];
  root: bigint;

  constructor(depth: number, poseidon: unknown, leaves?: bigint[]);
  buildTree(): void;
  hash(left: bigint, right: bigint): bigint;
  getProof(index: number): MerkleProof;
  insert(leaf: bigint): number;
}

export function buildNonMembershipProof(tree: MerkleTree, value: bigint): NonMembershipProof;
export function buildMerkleTree(leaves: bigint[], depth?: number): Promise<MerkleTree>;
