use std::fmt::Debug;

use ark_crypto_primitives::{crh::TwoToOneCRH, CRH};
use ark_ff::PrimeField;

use super::SortedMerkleTree;

impl<const HEIGHT: usize, F: PrimeField, H: CRH<Output = F> + TwoToOneCRH<Output = F>> Debug
    for SortedMerkleTree<HEIGHT, F, H>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SortedMerkleTree")
            .field("root", &self.root)
            .field("leaf", &self.leaf)
            .field("hashed_empty_leaf", &self.hashed_empty_leaf)
            .finish()
    }
}
