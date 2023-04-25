use std::{borrow::Borrow, fmt::Debug};

use ark_crypto_primitives::CRH;
use ark_ff::{to_bytes, PrimeField, ToBytes, ToConstraintField};

use crate::Filter;

use super::BloomFilter;

impl<const BITS: usize, const N_HASH: usize, F: PrimeField, H: CRH<Output = F>> ToConstraintField<F>
    for BloomFilter<BITS, N_HASH, F, H>
{
    /// Converts the bits vector of the Bloom filter into a vector of field elements.
    fn to_field_elements(&self) -> Option<Vec<F>> {
        Some(self.to_packed_bits())
    }
}

impl<const BITS: usize, const N_HASH: usize, F: PrimeField, H: CRH<Output = F>> PartialEq
    for BloomFilter<BITS, N_HASH, F, H>
where
    H::Parameters: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.bits == other.bits && self.hasher == other.hasher
    }
}

impl<const BITS: usize, const N_HASH: usize, F: PrimeField, H: CRH<Output = F>> Clone
    for BloomFilter<BITS, N_HASH, F, H>
{
    fn clone(&self) -> Self {
        Self {
            bits: self.bits,
            hasher: self.hasher.clone(),
        }
    }
}

impl<const BITS: usize, const N_HASH: usize, F: PrimeField, H: CRH<Output = F>> Debug
    for BloomFilter<BITS, N_HASH, F, H>
where
    H::Parameters: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BloomFilter")
            .field("bits", &self.bits)
            .field("hasher", &self.hasher)
            .finish()
    }
}

impl<const BITS: usize, const N_HASH: usize, F: PrimeField, H: CRH<Output = F>, Key> Filter<Key>
    for BloomFilter<BITS, N_HASH, F, H>
where
    H::Parameters: PartialEq + Debug,
    Key: ToBytes + PartialEq + Clone + Debug,
{
    type Parameter = Self;

    fn insert(parameter: &mut Self::Parameter, key: &dyn Borrow<Key>) {
        parameter.insert(&to_bytes!(key.borrow()).expect("Failed to convert to bytes"));
    }

    fn contains(parameter: &Self::Parameter, key: &dyn Borrow<Key>) -> bool {
        parameter.contains(&to_bytes!(key.borrow()).expect("Failed to convert to bytes"))
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use ark_bn254::Fr;
    use ark_ff::{BigInteger, One, PrimeField, Zero};
    use arkworks_mimc::{
        params::{
            mimc_7_91_bn254::{MIMC_7_91_BN254_PARAMS, MIMC_7_91_BN254_ROUND_KEYS},
            round_keys_contants_to_vec,
        },
        MiMC, MiMCNonFeistelCRH,
    };

    use crate::{bloom::BloomFilter, Filter};

    const BITS: usize = 253;
    const N_HASH: usize = 2;
    type BloomFilterTest =
        BloomFilter<BITS, N_HASH, Fr, MiMCNonFeistelCRH<Fr, MIMC_7_91_BN254_PARAMS>>;

    #[test]
    fn filter_trait_works() -> Result<(), Box<dyn Error>> {
        let mut bloom_filter = BloomFilterTest::new(MiMC::new(
            1,
            Fr::zero(),
            round_keys_contants_to_vec(&MIMC_7_91_BN254_ROUND_KEYS),
        ));
        let mut another_bloom_filter = bloom_filter.clone();

        let one = Fr::one();

        <BloomFilterTest as Filter<Fr>>::insert(&mut bloom_filter, &one);
        another_bloom_filter.insert(&one.into_repr().to_bytes_le());

        assert_eq!(
            bloom_filter.bits, another_bloom_filter.bits,
            "Bits should be equal"
        );

        Ok(())
    }
}
