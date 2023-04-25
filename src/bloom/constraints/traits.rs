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

#[cfg(test)]
mod tests {
    use std::error::Error;

    use ark_bn254::Fr;
    use ark_ff::{to_bytes, One, Zero};
    use ark_r1cs_std::{
        fields::fp::FpVar,
        prelude::{AllocVar, EqGadget},
    };
    use ark_relations::r1cs::ConstraintSystem;
    use arkworks_mimc::{
        constraints::{MiMCNonFeistelCRHGadget, MiMCVar},
        params::{
            mimc_7_91_bn254::{MIMC_7_91_BN254_PARAMS, MIMC_7_91_BN254_ROUND_KEYS},
            round_keys_contants_to_vec,
        },
        MiMC, MiMCNonFeistelCRH,
    };

    use crate::{
        bloom::{constraints::BloomFilterVar, BloomFilter},
        constraints::FilterGadget,
    };

    const BITS: usize = 8;
    const N_HASH: usize = 1;

    type BloomFilterTest =
        BloomFilter<BITS, N_HASH, Fr, MiMCNonFeistelCRH<Fr, MIMC_7_91_BN254_PARAMS>>;
    type BloomFilterVarTest = BloomFilterVar<
        BITS,
        N_HASH,
        Fr,
        MiMCNonFeistelCRH<Fr, MIMC_7_91_BN254_PARAMS>,
        MiMCNonFeistelCRHGadget<Fr, MIMC_7_91_BN254_PARAMS>,
    >;

    #[test]
    fn filter_gadget_trait_works() -> Result<(), Box<dyn Error>> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut bloom_filter = BloomFilterTest::new(MiMC::new(
            1,
            Fr::zero(),
            round_keys_contants_to_vec(&MIMC_7_91_BN254_ROUND_KEYS),
        ));
        let value = Fr::one();
        let before = bloom_filter.to_packed_bits();
        bloom_filter.insert(&to_bytes!(value)?);
        let after = bloom_filter.to_packed_bits();

        let mut filter_var = BloomFilterVarTest::new(
            Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(before))?,
            MiMCVar::new_constant(cs.clone(), bloom_filter.hasher)?,
        );

        let value_var = FpVar::new_witness(cs.clone(), || Ok(value))?;
        let after_var = Vec::<FpVar<_>>::new_witness(cs.clone(), || Ok(after))?;

        <BloomFilterVarTest as FilterGadget<_, Fr, FpVar<Fr>>>::insert(
            &mut filter_var,
            &value_var,
        )?;
        after_var.enforce_equal(&filter_var.packed_bits.0)?;

        assert!(cs.is_satisfied()?, "Should be satisfied");

        Ok(())
    }
}
