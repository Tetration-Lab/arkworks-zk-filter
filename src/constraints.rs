use ark_crypto_primitives::{CRHGadget, CRH};
use ark_ff::{FpParameters, PrimeField};
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{Boolean, EqGadget, FieldVar},
    uint8::UInt8,
    R1CSVar, ToBitsGadget,
};
use ark_relations::r1cs::SynthesisError;

use crate::utils::take_bits_gadget;

mod traits;
pub use traits::*;

/// Gadget for the `BloomFilter` struct.
#[derive(Debug, Clone)]
pub struct BloomFilterVar<
    const BITS: usize,
    F: PrimeField,
    H: CRH<Output = F>,
    HG: CRHGadget<H, F, OutputVar = FpVar<F>>,
> {
    pub packed_bits: PackedBitsVar<BITS, F>,
    pub hasher: HG::ParametersVar,
}

/// Gadget for a packed array of bits.
#[derive(Debug, Clone)]
pub struct PackedBitsVar<const BITS: usize, F: PrimeField>(pub Vec<FpVar<F>>);

impl<const BITS: usize, F: PrimeField> PackedBitsVar<BITS, F> {
    pub fn new(fields: Vec<FpVar<F>>) -> Self {
        Self(fields)
    }

    pub fn new_from_bits(bits: &[Boolean<F>]) -> Result<Self, SynthesisError> {
        assert!(!bits.is_empty(), "bits must not be empty");
        let max_size = F::Params::CAPACITY as usize;
        let zero = FpVar::zero();
        let elems = bits
            .chunks(max_size)
            .map(|chunk| -> Result<_, SynthesisError> {
                println!(
                    "{:?}",
                    chunk.iter().map(|b| b.value().unwrap()).collect::<Vec<_>>()
                );
                //let mut f = FpVar::new_witness(bits[0].cs(), || Ok(F::zero()))?;
                let mut f = FpVar::zero();
                for (i, bit) in chunk.iter().enumerate() {
                    f = &f
                        + &bit.select(&FpVar::constant(F::from(2_u64).pow([i as u64])), &zero)?;
                }
                Ok(f)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self(elems))
    }

    pub fn bits(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        Ok(self
            .0
            .iter()
            .map(|f| f.to_bits_le())
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .take(BITS)
            .collect())
    }
}

impl<
        const BITS: usize,
        F: PrimeField,
        H: CRH<Output = F>,
        HG: CRHGadget<H, F, OutputVar = FpVar<F>>,
    > BloomFilterVar<BITS, F, H, HG>
{
    /// Creates a new Bloom filter from an array of fields.
    /// The fields are packed into bits.
    pub fn new(packed_bits: Vec<FpVar<F>>, hasher: HG::ParametersVar) -> Self {
        Self {
            packed_bits: PackedBitsVar::new(packed_bits),
            hasher,
        }
    }

    /// Creates a new Bloom filter from an array of bits.
    pub fn new_from_bits(
        bits: Vec<Boolean<F>>,
        hasher: HG::ParametersVar,
    ) -> Result<Self, SynthesisError> {
        assert_eq!(
            bits.len(),
            BITS,
            "`bits` length does not match the number of bits"
        );
        Ok(Self {
            packed_bits: PackedBitsVar::new_from_bits(&bits)?,
            hasher,
        })
    }

    /// Inserts an input into the Bloom filter.
    /// Returns the index of the bit that was set.
    pub fn insert(&mut self, input: &[UInt8<F>]) -> Result<FpVar<F>, SynthesisError> {
        let hash = HG::evaluate(&self.hasher, input)?;
        let index = take_bits_gadget(&hash, BITS)?;
        let mut bits = self.packed_bits.bits()?;
        for i in 0..BITS {
            let index_var = FpVar::constant(F::from(i as u64));
            bits[i] = bits[i].or(&index_var.is_eq(&index)?)?;
        }
        self.packed_bits = PackedBitsVar::new_from_bits(&bits)?;
        Ok(index)
    }

    /// Checks if an input is in the Bloom filter.
    /// Returns true if the input is in the Bloom filter.
    pub fn contains(&self, input: &[UInt8<F>]) -> Result<Boolean<F>, SynthesisError> {
        let hash = HG::evaluate(&self.hasher, input)?;
        let index = take_bits_gadget(&hash, BITS)?;
        let bits = self.packed_bits.bits()?;
        let mut result = Boolean::FALSE;
        for i in 0..BITS {
            let index_var = FpVar::constant(F::from(i as u64));
            result = result.or(&index_var.is_eq(&index)?.and(&bits[i])?)?;
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::Zero;
    use ark_r1cs_std::{
        fields::fp::FpVar,
        prelude::{AllocVar, Boolean, EqGadget},
        uint8::UInt8,
        R1CSVar,
    };
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use arkworks_mimc::{
        constraints::{MiMCNonFeistelCRHGadget, MiMCVar},
        params::{
            mimc_7_91_bn254::{MIMC_7_91_BN254_PARAMS, MIMC_7_91_BN254_ROUND_KEYS},
            round_keys_contants_to_vec,
        },
        MiMC, MiMCNonFeistelCRH,
    };

    use crate::{constraints::PackedBitsVar, BloomFilter};

    use super::BloomFilterVar;

    const BITS: usize = 8;
    type BloomFilterTest = BloomFilter<BITS, Fr, MiMCNonFeistelCRH<Fr, MIMC_7_91_BN254_PARAMS>>;
    type BloomFilterVarTest = BloomFilterVar<
        BITS,
        Fr,
        MiMCNonFeistelCRH<Fr, MIMC_7_91_BN254_PARAMS>,
        MiMCNonFeistelCRHGadget<Fr, MIMC_7_91_BN254_PARAMS>,
    >;

    pub struct InsertCircuit {
        pub before_bits: Vec<Fr>,
        pub after_bits: Vec<Fr>,
        pub input: Vec<u8>,
        pub hasher: MiMC<Fr, MIMC_7_91_BN254_PARAMS>,
    }

    impl ConstraintSynthesizer<Fr> for InsertCircuit {
        fn generate_constraints(
            self,
            cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
        ) -> ark_relations::r1cs::Result<()> {
            let before_bits = Vec::<FpVar<Fr>>::new_input(cs.clone(), || Ok(self.before_bits))?;
            let after_bits = Vec::<FpVar<Fr>>::new_input(cs.clone(), || Ok(self.after_bits))?;
            let input = Vec::<UInt8<Fr>>::new_witness(cs.clone(), || Ok(self.input))?;
            let hasher = MiMCVar::new_constant(cs, self.hasher)?;

            let mut filter = BloomFilterVarTest::new(before_bits, hasher);
            let _ = filter.insert(&input)?;

            filter.packed_bits.0.enforce_equal(&after_bits)?;

            Ok(())
        }
    }

    pub struct ContainCircuit {
        pub bits: Vec<Fr>,
        pub input: Vec<u8>,
        pub hasher: MiMC<Fr, MIMC_7_91_BN254_PARAMS>,
    }

    impl ConstraintSynthesizer<Fr> for ContainCircuit {
        fn generate_constraints(
            self,
            cs: ark_relations::r1cs::ConstraintSystemRef<Fr>,
        ) -> ark_relations::r1cs::Result<()> {
            let bits = Vec::<FpVar<Fr>>::new_input(cs.clone(), || Ok(self.bits))?;
            let input = Vec::<UInt8<Fr>>::new_witness(cs.clone(), || Ok(self.input))?;
            let hasher = MiMCVar::new_constant(cs, self.hasher)?;

            let filter = BloomFilterVarTest::new(bits, hasher);
            let result = filter.contains(&input)?;

            // Enforce that the bits is FALSE -> not in the filter
            result.enforce_equal(&Boolean::FALSE)?;

            Ok(())
        }
    }

    #[test]
    fn insert_works() {
        let mut filter = BloomFilterTest::new(MiMC::new(
            1,
            Fr::zero(),
            round_keys_contants_to_vec(&MIMC_7_91_BN254_ROUND_KEYS),
        ));
        let bits_before = filter.to_packed_bits();
        let input = b"hello world";
        let _ = filter.insert(input);
        let bits_after = filter.to_packed_bits();

        let cs = ConstraintSystem::<Fr>::new_ref();
        InsertCircuit {
            before_bits: bits_before,
            after_bits: bits_after,
            input: input.to_vec(),
            hasher: filter.hasher.clone(),
        }
        .generate_constraints(cs.clone())
        .expect("should generate constraints");
        assert!(
            cs.is_satisfied().expect("should calculate satisfiability"),
            "should be satisfied"
        );
    }

    #[test]
    fn contains_works() {
        let mut filter = BloomFilterTest::new(MiMC::new(
            1,
            Fr::zero(),
            round_keys_contants_to_vec(&MIMC_7_91_BN254_ROUND_KEYS),
        ));
        let input = b"hello world";
        let _ = filter.insert(input);
        let another_input = b"hello world!";

        let cs = ConstraintSystem::<Fr>::new_ref();
        ContainCircuit {
            bits: filter.to_packed_bits(),
            input: another_input.to_vec(),
            hasher: filter.hasher.clone(),
        }
        .generate_constraints(cs.clone())
        .expect("should generate constraints");
        assert!(
            cs.is_satisfied().expect("should calculate satisfiability"),
            "should be satisfied"
        );
    }

    #[test]
    fn correctly_pack_bits() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut filter = BloomFilterTest::new(MiMC::new(
            1,
            Fr::zero(),
            round_keys_contants_to_vec(&MIMC_7_91_BN254_ROUND_KEYS),
        ));

        filter.insert(b"1");

        let bits = Vec::<Boolean<Fr>>::new_input(cs, || Ok(filter.bits.to_vec())).unwrap();
        let packed = PackedBitsVar::<BITS, _>::new_from_bits(&bits).expect("Should pack bits");

        let packed_value = packed.0.value().unwrap();
        let packed_bits_value = packed.bits().unwrap().value().unwrap();

        assert_eq!(packed_bits_value, filter.bits, "Bits should be equal");
        assert_eq!(
            packed_value,
            filter.to_packed_bits(),
            "Packed bits should be equal"
        );
    }
}
