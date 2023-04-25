use std::{borrow::Borrow, fmt::Debug};

use ark_crypto_primitives::{CRHGadget, CRH};
use ark_ff::{PrimeField, ToBytes};
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, AllocationMode, Boolean, EqGadget},
    ToBytesGadget, ToConstraintFieldGadget,
};
use ark_relations::r1cs::{Namespace, SynthesisError};

use crate::constraints::FilterGadget;

use super::{BloomFilterVar, PackedBitsVar};

impl<const BITS: usize, F: PrimeField> ToConstraintFieldGadget<F> for PackedBitsVar<BITS, F> {
    /// Converts the bits vector of the Bloom filter into a vector of field elements.
    fn to_constraint_field(&self) -> Result<Vec<FpVar<F>>, SynthesisError> {
        Ok(self.0.clone())
    }
}

impl<const BITS: usize, F: PrimeField> EqGadget<F> for PackedBitsVar<BITS, F> {
    fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        self.0.is_eq(&other.0)
    }
}

impl<const BITS: usize, F: PrimeField> AllocVar<[F], F> for PackedBitsVar<BITS, F> {
    fn new_variable<T: Borrow<[F]>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let value = f()?;
        Ok(PackedBitsVar(Vec::<FpVar<F>>::new_variable(
            cs,
            || Ok(value),
            mode,
        )?))
    }
}

impl<
        const BITS: usize,
        const N_HASH: usize,
        F: PrimeField,
        H: CRH<Output = F>,
        HG: CRHGadget<H, F, OutputVar = FpVar<F>>,
    > std::fmt::Debug for BloomFilterVar<BITS, N_HASH, F, H, HG>
where
    HG::ParametersVar: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BloomFilterVar")
            .field("packed_bits", &self.packed_bits)
            .field("hasher", &self.hasher)
            .finish()
    }
}

impl<
        const BITS: usize,
        const N_HASH: usize,
        F: PrimeField,
        H: CRH<Output = F>,
        HG: CRHGadget<H, F, OutputVar = FpVar<F>>,
    > Clone for BloomFilterVar<BITS, N_HASH, F, H, HG>
{
    fn clone(&self) -> Self {
        Self {
            packed_bits: self.packed_bits.clone(),
            hasher: self.hasher.clone(),
        }
    }
}

impl<
        const BITS: usize,
        const N_HASH: usize,
        F: PrimeField,
        H: CRH<Output = F>,
        HG: CRHGadget<H, F, OutputVar = FpVar<F>>,
    > EqGadget<F> for BloomFilterVar<BITS, N_HASH, F, H, HG>
where
    HG::ParametersVar: EqGadget<F>,
{
    fn is_eq(&self, other: &Self) -> Result<Boolean<F>, SynthesisError> {
        self.packed_bits
            .is_eq(&other.packed_bits)?
            .and(&self.hasher.is_eq(&other.hasher)?)
    }
}

impl<
        const BITS: usize,
        const N_HASH: usize,
        F: PrimeField,
        H: CRH<Output = F>,
        HG: CRHGadget<H, F, OutputVar = FpVar<F>>,
        Key,
        KeyVar,
    > FilterGadget<F, Key, KeyVar> for BloomFilterVar<BITS, N_HASH, F, H, HG>
where
    Key: ToBytes + PartialEq + Clone + Debug,
    KeyVar: AllocVar<Key, F> + ToBytesGadget<F> + EqGadget<F> + Clone + Debug,
    HG::ParametersVar: EqGadget<F> + Debug,
{
    type ParameterVar = Self;

    fn insert(
        param: &mut Self::ParameterVar,
        key: &dyn Borrow<KeyVar>,
    ) -> Result<(), SynthesisError> {
        let _ = param.insert(&key.borrow().to_bytes()?)?;
        Ok(())
    }

    fn contains(
        param: &Self::ParameterVar,
        key: &dyn Borrow<KeyVar>,
    ) -> Result<Boolean<F>, SynthesisError> {
        param.contains(&key.borrow().to_bytes()?)
    }
}
