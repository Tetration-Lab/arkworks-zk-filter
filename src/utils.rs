use ark_ff::{to_bytes, PrimeField, ToBytes};
use ark_relations::r1cs::SynthesisError;
use ark_std::log2;

#[cfg(feature = "r1cs")]
use ark_r1cs_std::{fields::fp::FpVar, R1CSVar, ToBytesGadget};

/// Read value as bits in LE and take the first `max` bits then wraps around `max`.
pub fn take_bits<T: ToBytes>(value: &T, max: usize) -> usize {
    let n_bits = log2(max) as usize;
    let bytes = to_bytes!(value).expect("Failed to convert to bytes");
    let sum: usize = bytes
        .iter()
        .flat_map(|b| (0..8).map(move |i| (b >> i) & 1u8 == 1u8))
        .take(n_bits)
        .fold(0, |acc, b| (acc << 1) | (b as usize));

    let max_index = max - 1;
    match sum > max_index {
        true => sum - max_index,
        false => sum,
    }
}

/// Read value as bits in LE and take the first `max` bits then wraps around `max`.
#[cfg(feature = "r1cs")]
pub fn take_bits_gadget<F: PrimeField, T: ToBytesGadget<F> + R1CSVar<F>>(
    value: &T,
    max: usize,
) -> Result<FpVar<F>, SynthesisError> {
    use std::cmp::Ordering;

    use ark_r1cs_std::{prelude::FieldVar, ToBitsGadget};

    let n_bits = log2(max) as usize;
    let two = FpVar::constant(F::from(2u64));
    let bits = value.to_bytes()?.to_bits_le()?;
    let mut index = FpVar::zero();
    for bit in bits.into_iter().take(n_bits) {
        index = &index * &two + &FpVar::from(bit);
    }

    let max_index = FpVar::constant(F::from((max as u64) - 1));
    index
        .is_cmp(&max_index, Ordering::Greater, false)?
        .select(&(&index - &max_index), &index)
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use ark_r1cs_std::{fields::fp::FpVar, prelude::AllocVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;

    use super::{take_bits, take_bits_gadget};

    #[test]
    fn correct_bits() -> Result<(), Box<dyn Error>> {
        let rng = &mut test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();

        let value = Fr::rand(rng);
        let value_var = FpVar::new_witness(cs, || Ok(value))?;

        let take = 9usize;
        let taken = take_bits(&value, take);
        let taken_var = take_bits_gadget(&value_var, take)?;

        assert_eq!(Fr::from(taken as u64), taken_var.value()?);

        Ok(())
    }
}
