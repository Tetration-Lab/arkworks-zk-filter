use ark_crypto_primitives::CRH;
use ark_ff::{BigInteger, FpParameters, PrimeField};

use crate::utils::take_bits;

#[cfg(feature = "r1cs")]
pub mod constraints;

mod traits;
pub use traits::*;

/// A Bloom filter.
///
/// The Bloom filter is a probabilistic data structure that can be used to test if an element is in a set.
///
/// For the most optimized bits, the number of bits should be a multiple of the number of carrying bits in the field.
/// For example, if the field is scalar field of BN254, then the number of bits should be a multiple of 253.
///
/// The false positive rate of the Bloom filter is `1 - e^(-k * n / m)`
/// Where `k` is the number of hash functions, `n` is the number of elements in the set, and `m` is the number of bits in the Bloom filter.
pub struct BloomFilter<const BITS: usize, const N_HASH: usize, F: PrimeField, H: CRH<Output = F>> {
    pub bits: [bool; BITS],
    pub hasher: H::Parameters,
}

impl<const BITS: usize, const N_HASH: usize, F: PrimeField, H: CRH<Output = F>>
    BloomFilter<BITS, N_HASH, F, H>
{
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

    /// Creates a new Bloom filter from an array of fields.
    /// The fields are packed into bits.
    pub fn new_from_packed_bits(packed_bits: &[F], hasher: H::Parameters) -> Self {
        let max_size = F::Params::CAPACITY as usize;
        assert!(packed_bits.len() * max_size >= BITS, "Not enough bits");
        let bits = packed_bits
            .iter()
            .flat_map(|f| f.into_repr().to_bits_le())
            .take(BITS)
            .collect::<Vec<_>>();
        Self {
            bits: bits.try_into().expect("Failed to convert to sized array"),
            hasher,
        }
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
    pub fn insert(&mut self, input: &[u8]) -> [usize; N_HASH] {
        let mut positions = [0; N_HASH];
        let mut hashed = <H as CRH>::evaluate(&self.hasher, input).expect("Hash failed");
        for position in positions.iter_mut() {
            let pos = take_bits(&hashed, BITS);
            self.bits[pos] = true;
            *position = pos;
            hashed = <H as CRH>::evaluate(&self.hasher, &hashed.into_repr().to_bytes_le())
                .expect("Hash failed");
        }
        positions
    }

    /// Checks if an input is in the Bloom filter.
    /// Returns true if the input is in the Bloom filter.
    pub fn contains(&self, input: &[u8]) -> bool {
        let mut hashed = <H as CRH>::evaluate(&self.hasher, input).expect("Hash failed");
        (0..N_HASH).all(|_| {
            let pos = take_bits(&hashed, BITS);
            hashed = <H as CRH>::evaluate(&self.hasher, &hashed.into_repr().to_bytes_le())
                .expect("Hash failed");
            self.bits[pos]
        })
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

    use crate::bloom::BloomFilter;

    const BITS: usize = 253;
    const N_HASH: usize = 2;
    type BloomFilterTest =
        BloomFilter<BITS, N_HASH, Fr, MiMCNonFeistelCRH<Fr, MIMC_7_91_BN254_PARAMS>>;

    #[test]
    fn correct_field_elements() {
        let mut bloom_filter = BloomFilterTest::new(MiMC::new(
            1,
            Fr::zero(),
            round_keys_contants_to_vec(&MIMC_7_91_BN254_ROUND_KEYS),
        ));
        bloom_filter.insert(b"toyoyo");
        bloom_filter.insert(b"toyoyo!");
        let fs = bloom_filter
            .to_field_elements()
            .expect("Should convert to field elements");
        assert_eq!(fs.len(), 1, "Should be one field element");
        assert_eq!(
            BloomFilterTest::new_from_packed_bits(
                &fs,
                MiMC::new(
                    1,
                    Fr::zero(),
                    round_keys_contants_to_vec(&MIMC_7_91_BN254_ROUND_KEYS),
                )
            )
            .bits,
            bloom_filter.bits,
            "Should be equal"
        );
    }

    #[test]
    fn correct_index() {
        let mut bloom_filter = BloomFilterTest::new(MiMC::new(
            1,
            Fr::zero(),
            round_keys_contants_to_vec(&MIMC_7_91_BN254_ROUND_KEYS),
        ));
        assert!(bloom_filter.bits.iter().all(|b| !b), "Bits should be empty");
        let indexes = bloom_filter.insert(b"hello");
        for index in indexes {
            assert!(bloom_filter.bits[index], "Bit {index} should be set");
        }
    }

    #[test]
    fn correct_contains() {
        let mut bloom_filter = BloomFilterTest::new(MiMC::new(
            1,
            Fr::zero(),
            round_keys_contants_to_vec(&MIMC_7_91_BN254_ROUND_KEYS),
        ));
        bloom_filter.insert(b"hello");
        assert!(
            bloom_filter.contains(b"hello"),
            "Bloom filter should contain input"
        );
        assert!(
            !bloom_filter.contains(b"hello!"),
            "Bloom filter should not contain input"
        );
    }
}
