use ark_crypto_primitives::CRH;
use ark_ff::{BigInteger, FpParameters, PrimeField, ToConstraintField};
use utils::take_bits;

#[cfg(feature = "r1cs")]
pub mod constraints;

mod utils;

/// A Bloom filter.
///
/// The Bloom filter is a probabilistic data structure that can be used to test if an element is in a set.
///
/// The false positive rate of the Bloom filter is `1 - e^(-k * n / m)`
/// Where `k` is the number of hash functions, `n` is the number of elements in the set, and `m` is the number of bits in the Bloom filter.
#[derive(Debug, Clone)]
pub struct BloomFilter<const BITS: usize, F: PrimeField, H: CRH<Output = F>> {
    pub bits: [bool; BITS],
    pub hasher: H::Parameters,
}

impl<const BITS: usize, F: PrimeField, H: CRH<Output = F>> ToConstraintField<F>
    for BloomFilter<BITS, F, H>
{
    /// Converts the bits vector of the Bloom filter into a vector of field elements.
    fn to_field_elements(&self) -> Option<Vec<F>> {
        Some(self.to_packed_bits())
    }
}

impl<const BITS: usize, F: PrimeField, H: CRH<Output = F>> BloomFilter<BITS, F, H> {
    /// Creates a new Bloom filter.
    pub fn new(hasher: H::Parameters) -> Self {
        Self {
            bits: [false; BITS],
            hasher,
        }
    }

    /// Creates a new Bloom filter from an array of bits.
    pub fn new_from_bits(bits: [bool; BITS], hasher: H::Parameters) -> Self {
        Self { bits, hasher }
    }

    /// Sets the bits of the Bloom filter.
    pub fn set_bits(&mut self, bits: [bool; BITS]) {
        self.bits = bits;
    }

    /// Resets the bits of the Bloom filter.
    pub fn reset_bits(&mut self) {
        self.bits = [false; BITS];
    }

    /// Inserts an input into the Bloom filter.
    /// Returns the index of the bit that was set.
    pub fn insert(&mut self, input: &[u8]) -> usize {
        let hash = <H as CRH>::evaluate(&self.hasher, input).expect("Hash failed");
        let pos = take_bits(&hash, BITS);
        self.bits[pos] = true;
        pos
    }

    /// Checks if an input is in the Bloom filter.
    /// Returns true if the input is in the Bloom filter.
    pub fn contains(&self, input: &[u8]) -> bool {
        let hash = <H as CRH>::evaluate(&self.hasher, input).expect("Hash failed");
        let pos = take_bits(&hash, BITS);
        self.bits[pos]
    }

    /// Converts the bits vector of the Bloom filter into a vector of field elements.
    /// The bits are packed into field elements.
    pub fn to_packed_bits(&self) -> Vec<F> {
        let max_size = F::Params::CAPACITY as usize;
        let elems = self
            .bits
            .chunks(max_size)
            .map(|chunk| {
                F::from_repr(F::BigInt::from_bits_le(chunk))
                    .expect("Failed to convert bits to field element")
            })
            .collect::<Vec<_>>();
        elems
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::{ToConstraintField, Zero};
    use arkworks_mimc::{
        params::{
            mimc_7_91_bn254::{MIMC_7_91_BN254_PARAMS, MIMC_7_91_BN254_ROUND_KEYS},
            round_keys_contants_to_vec,
        },
        MiMC, MiMCNonFeistelCRH,
    };

    use crate::BloomFilter;

    type BloomFilterTest = BloomFilter<253, Fr, MiMCNonFeistelCRH<Fr, MIMC_7_91_BN254_PARAMS>>;

    #[test]
    fn correct_field_elements() {
        let mut bloom_filter = BloomFilterTest::new(MiMC::new(
            1,
            Fr::zero(),
            round_keys_contants_to_vec(&MIMC_7_91_BN254_ROUND_KEYS),
        ));
        //vec![0; 256].to_field_elements();
        bloom_filter.insert(b"toyoyo");
        bloom_filter.insert(b"toyoyo!");
        let fs = bloom_filter
            .to_field_elements()
            .expect("Should convert to field elements");
        println!("{:?}", fs.len());
        println!("{:?}", fs);
    }

    #[test]
    fn correct_index() {
        let mut bloom_filter = BloomFilterTest::new(MiMC::new(
            1,
            Fr::zero(),
            round_keys_contants_to_vec(&MIMC_7_91_BN254_ROUND_KEYS),
        ));
        let ind = bloom_filter.insert(b"hello");
        assert_eq!(ind, 58);
    }
}
