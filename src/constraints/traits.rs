use std::borrow::Borrow;

use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, AllocationMode, Boolean, EqGadget},
    ToConstraintFieldGadget,
};
use ark_relations::r1cs::{Namespace, SynthesisError};

use super::PackedBitsVar;

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
