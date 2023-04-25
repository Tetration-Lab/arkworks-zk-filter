//! This crate provides implementations of various filters.
//! A filter is a data structure that can be used to test whether an element is a member of a set.
//! It may produce false positives, but never false negatives.

/// Bloom Filter Module
pub mod bloom;
/// Sorted Merkle Tree Module
pub mod sorted_merkle_tree;

mod utils;

/// Filter trait
pub trait Filter<Key>
where
    Key: ark_ff::ToBytes + PartialEq + Clone + std::fmt::Debug,
{
    type Parameter: PartialEq + Clone + std::fmt::Debug;

    fn insert(parameter: &mut Self::Parameter, key: &dyn std::borrow::Borrow<Key>);
    fn contains(parameter: &Self::Parameter, key: &dyn std::borrow::Borrow<Key>) -> bool;
}

#[cfg(feature = "r1cs")]
pub mod constraints {
    use std::borrow::Borrow;

    use ark_ff::{PrimeField, ToBytes};
    use ark_r1cs_std::{
        prelude::{AllocVar, Boolean, EqGadget},
        ToBytesGadget,
    };
    use ark_relations::r1cs::SynthesisError;

    /// FilterGadget trait specifies the constraints for a filter.
    pub trait FilterGadget<F: PrimeField, Key, KeyVar>
    where
        Key: ToBytes + PartialEq + Clone + std::fmt::Debug,
        KeyVar: AllocVar<Key, F> + ToBytesGadget<F> + EqGadget<F> + Clone + std::fmt::Debug,
    {
        type ParameterVar: EqGadget<F> + Clone + std::fmt::Debug;

        fn insert(
            param: &mut Self::ParameterVar,
            key: &dyn Borrow<KeyVar>,
        ) -> Result<(), SynthesisError>;
        fn contains(
            param: &Self::ParameterVar,
            key: &dyn Borrow<KeyVar>,
        ) -> Result<Boolean<F>, SynthesisError>;
    }
}
