use ark_ff::{PrimeField, ToBytes};
use ark_relations::r1cs::SynthesisError;
use ark_std::log2;

#[cfg(feature = "r1cs")]
use ark_r1cs_std::{fields::fp::FpVar, R1CSVar, ToBytesGadget};

/// Read value as bits in LE and take the first `max` bits then wraps around `max`.
pub fn take_bits<T: ToBytes>(value: &T, max: usize) -> usize {
    let n_bits = log2(max) as usize;
    let mut bytes = vec![];
    value.write(&mut bytes).expect("Failed to write to bytes");
    let sum: usize = bytes
        .iter()
        .rev()
        .flat_map(|b| (0..8).map(move |i| (b >> i) & 1 == 1))
        .take(n_bits)
        .fold(0, |acc, b| {
            (acc << 1)
                + match b {
                    true => 1,
                    false => 0,
                }
        });

    match sum > max - 1 {
        true => sum - max,
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
    let max_index = FpVar::constant(F::from(max as u64 - 1));
    let bits = value.to_bytes()?.to_bits_le()?;
    //let mut index = FpVar::new_witness(ns!(value.cs(), "index"), || Ok(F::zero()))?;
    let mut index = FpVar::zero();
    for bit in bits.into_iter().take(n_bits) {
        index = &index + &FpVar::from(bit);
    }
    index
        .is_cmp(&max_index, Ordering::Greater, false)?
        .select(&(&index - &max_index), &index)
}
