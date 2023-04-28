use std::{cell::RefCell, cmp::Ordering};

use ark_crypto_primitives::{
    crh::{TwoToOneCRH, TwoToOneCRHGadget},
    CRHGadget, CRH,
};
use ark_ff::{BigInteger, FpParameters, PrimeField};
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, Boolean, EqGadget, FieldVar},
    R1CSVar, ToBytesGadget,
};
use ark_relations::{ns, r1cs::SynthesisError};

use super::SortedMerkleTree;

pub struct SortedMerkleTreeVar<
    const HEIGHT: usize,
    F: PrimeField,
    H: CRH<Output = F> + TwoToOneCRH<Output = F>,
    HG: CRHGadget<H, F, OutputVar = FpVar<F>> + TwoToOneCRHGadget<H, F, OutputVar = FpVar<F>>,
> {
    pub tree: RefCell<SortedMerkleTree<HEIGHT, F, H>>,
    pub root: FpVar<F>,
    pub param_crh: <HG as CRHGadget<H, F>>::ParametersVar,
    pub param_tto_crh: <HG as TwoToOneCRHGadget<H, F>>::ParametersVar,
}

impl<
        const HEIGHT: usize,
        F: PrimeField,
        H: CRH<Output = F> + TwoToOneCRH<Output = F>,
        HG: CRHGadget<H, F, OutputVar = FpVar<F>> + TwoToOneCRHGadget<H, F, OutputVar = FpVar<F>>,
    > SortedMerkleTreeVar<HEIGHT, F, H, HG>
{
    pub const LEAF_LEN: usize = 1 << (HEIGHT - 1);

    pub fn new(
        tree: RefCell<SortedMerkleTree<HEIGHT, F, H>>,
        root: FpVar<F>,
        param_crh: <HG as CRHGadget<H, F>>::ParametersVar,
        param_tto_crh: <HG as TwoToOneCRHGadget<H, F>>::ParametersVar,
    ) -> Self {
        Self {
            tree,
            root,
            param_crh,
            param_tto_crh,
        }
    }

    /// Check if the leaf is in the tree
    /// Allocate the merkle proof as witness
    pub fn contains(&self, value: &FpVar<F>) -> Result<Boolean<F>, SynthesisError> {
        let cs = self.root.cs();
        let tree = self.tree.borrow();
        let max = {
            let mut bi = <<F as PrimeField>::Params as FpParameters>::MODULUS;
            bi.sub_noborrow(&F::BigInt::from(1));
            F::from_repr(bi).expect("Should convert from modulus")
        };
        println!("max: {}", max);
        let (is_left, nearby, path) = match value.value() {
            Ok(value) => {
                let hashed =
                    <H as CRH>::evaluate(&tree.param_crh, &value.into_repr().to_bytes_le())
                        .expect("Should able to hash");

                let (nearby, mut index, mut proof) = match tree.leaf.binary_search(&hashed) {
                    Ok(i) => match (i != 0, i != SortedMerkleTree::<HEIGHT, F, H>::LEAF_LEN) {
                        (true, true) => (
                            (tree.leaf[i - 1], tree.leaf[i + 1]),
                            (Some(i - 1), Some(i + 1)),
                            (vec![], vec![]),
                        ),
                        (true, false) => (
                            (
                                tree.leaf[SortedMerkleTree::<HEIGHT, F, H>::LEAF_LEN - 1],
                                max,
                            ),
                            (Some(i - 1), None),
                            (vec![], vec![F::zero(); HEIGHT - 2]),
                        ),
                        (false, true) => (
                            (F::zero(), tree.leaf[1]),
                            (None, Some(i + 1)),
                            (vec![F::zero(); HEIGHT - 2], vec![]),
                        ),
                        (false, false) => (
                            (F::zero(), max),
                            (None, None),
                            (vec![F::zero(); HEIGHT - 2], vec![F::zero(); HEIGHT - 2]),
                        ),
                    },
                    Err(_) => (
                        (F::zero(), max),
                        (None, None),
                        (vec![F::zero(); HEIGHT - 2], vec![F::zero(); HEIGHT - 2]),
                    ),
                };

                let mut is_left = (vec![], vec![]);
                match index {
                    (None, None) => {}
                    _ => {
                        let mut tmp_leaf = tree.leaf.to_vec();
                        while tmp_leaf.len() > 1 {
                            if let Some(i) = &mut index.0 {
                                match *i % 2 == 0 {
                                    true => {
                                        proof.0.push(tmp_leaf[*i + 1]);
                                        is_left.0.push(true);
                                    }
                                    false => {
                                        proof.0.push(tmp_leaf[*i - 1]);
                                        is_left.0.push(false);
                                    }
                                }
                                *i /= 2;
                            }

                            if let Some(i) = &mut index.1 {
                                match *i % 2 == 0 {
                                    true => {
                                        proof.1.push(tmp_leaf[*i + 1]);
                                        is_left.1.push(true);
                                    }
                                    false => {
                                        proof.1.push(tmp_leaf[*i - 1]);
                                        is_left.1.push(false);
                                    }
                                }
                                *i /= 2;
                            }

                            tmp_leaf = tmp_leaf
                                .chunks(2)
                                .map(|chunk| {
                                    let left = chunk[0];
                                    let right = chunk[1];
                                    <H as TwoToOneCRH>::evaluate(
                                        &tree.param_tto_crh,
                                        &left.into_repr().to_bytes_le(),
                                        &right.into_repr().to_bytes_le(),
                                    )
                                    .expect("Should able to hash")
                                })
                                .collect::<Vec<_>>();
                        }
                    }
                };

                let left_is_left_var =
                    Vec::<Boolean<F>>::new_witness(ns!(cs, "proof: left is left"), || {
                        Ok(is_left.0)
                    })?;
                let right_is_left_var =
                    Vec::<Boolean<F>>::new_witness(ns!(cs, "proof: right is left"), || {
                        Ok(is_left.1)
                    })?;
                let left_hashed_var =
                    FpVar::new_witness(ns!(cs, "proof: left hash"), || Ok(nearby.0))?;
                let left_proof_var =
                    Vec::<FpVar<F>>::new_witness(ns!(cs, "proof: left path"), || Ok(proof.0))?;
                let right_hashed_var =
                    FpVar::new_witness(ns!(cs, "proof: right hash"), || Ok(nearby.1))?;
                let right_proof_var =
                    Vec::<FpVar<F>>::new_witness(ns!(cs, "proof: right path"), || Ok(proof.1))?;

                (
                    (left_is_left_var, right_is_left_var),
                    (left_hashed_var, right_hashed_var),
                    (left_proof_var, right_proof_var),
                )
                //let hashed_var = FpVar::new_witness(ns!(cs, "proof: hashed"), || Ok(hashed))?;
                //let proof_var = Vec::<FpVar<F>>::new_witness(ns!(cs, "proof: path"), || Ok(proof))?;

                //(proof_index, hashed_var, proof_var)
            }
            Err(_) => {
                let is_left: (Vec<Boolean<F>>, Vec<Boolean<F>>) = (
                    Vec::<Boolean<F>>::new_witness(ns!(cs, "proof: left is left"), || {
                        Ok(vec![false; HEIGHT - 2])
                    })?,
                    Vec::<Boolean<F>>::new_witness(ns!(cs, "proof: right is left"), || {
                        Ok(vec![false; HEIGHT - 2])
                    })?,
                );
                let nearby = (
                    FpVar::new_witness(ns!(cs, "proof: left hash"), || Ok(F::zero()))?,
                    FpVar::new_witness(ns!(cs, "proof: right hash"), || Ok(F::zero()))?,
                );
                let proof = (
                    Vec::<FpVar<F>>::new_witness(ns!(cs, "proof: path"), || {
                        Ok(vec![F::zero(); HEIGHT - 2])
                    })?,
                    Vec::<FpVar<F>>::new_witness(ns!(cs, "proof: path"), || {
                        Ok(vec![F::zero(); HEIGHT - 2])
                    })?,
                );
                (is_left, nearby, proof)
            }
        };

        println!("length: {}", is_left.0.len());
        println!("height: {}", HEIGHT);
        println!("leaf_len: {}", Self::LEAF_LEN);

        let min = FpVar::constant(F::zero());
        let max = FpVar::constant(max);

        let calculated_hashed_leaf =
            <HG as CRHGadget<H, F>>::evaluate(&self.param_crh, &value.to_bytes()?)?;
        let calculated_root = path
            .0
            .iter()
            .zip(path.1.iter())
            .zip(is_left.0.iter())
            .zip(is_left.1.iter())
            .try_fold(
                nearby.clone(),
                |(prev_left, prev_right),
                 (((next_left, next_right), left_is_left), right_is_left)|
                 -> Result<_, SynthesisError> {
                    Ok((
                        left_is_left.select(
                            &<HG as TwoToOneCRHGadget<H, F>>::evaluate(
                                &self.param_tto_crh,
                                &prev_left.to_bytes()?,
                                &next_left.to_bytes()?,
                            )?,
                            &<HG as TwoToOneCRHGadget<H, F>>::evaluate(
                                &self.param_tto_crh,
                                &next_left.to_bytes()?,
                                &prev_left.to_bytes()?,
                            )?,
                        )?,
                        right_is_left.select(
                            &<HG as TwoToOneCRHGadget<H, F>>::evaluate(
                                &self.param_tto_crh,
                                &prev_right.to_bytes()?,
                                &next_right.to_bytes()?,
                            )?,
                            &<HG as TwoToOneCRHGadget<H, F>>::evaluate(
                                &self.param_tto_crh,
                                &next_right.to_bytes()?,
                                &prev_right.to_bytes()?,
                            )?,
                        )?,
                    ))
                },
            )?;
        let is_left_valid = calculated_hashed_leaf
            .is_cmp(&nearby.0, Ordering::Greater, false)?
            .and(
                &nearby
                    .0
                    .is_eq(&min)?
                    .or(&calculated_root.0.is_eq(&self.root)?)?,
            )?;
        let is_right_valid = calculated_hashed_leaf
            .is_cmp(&nearby.1, Ordering::Less, false)?
            .and(
                &nearby
                    .1
                    .is_eq(&max)?
                    .or(&calculated_root.1.is_eq(&self.root)?)?,
            )?;

        //TODO: construct index using is_left vec and check index right = index left + 1

        Ok(is_left_valid.and(&is_right_valid)?)
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, error::Error};

    use ark_bn254::Fr;
    use ark_ff::Zero;
    use ark_r1cs_std::{fields::fp::FpVar, prelude::AllocVar};
    use ark_relations::r1cs::ConstraintSystem;
    use arkworks_mimc::{
        constraints::{MiMCNonFeistelCRHGadget, MiMCVar},
        params::{
            mimc_7_91_bn254::{MIMC_7_91_BN254_PARAMS, MIMC_7_91_BN254_ROUND_KEYS},
            round_keys_contants_to_vec,
        },
        MiMC, MiMCNonFeistelCRH,
    };

    use crate::sorted_merkle_tree::SortedMerkleTree;

    use super::SortedMerkleTreeVar;

    type Tree = SortedMerkleTree<5, Fr, Hash>;
    type TreeVar = SortedMerkleTreeVar<5, Fr, Hash, HashGadget>;
    type Hash = MiMCNonFeistelCRH<Fr, MIMC_7_91_BN254_PARAMS>;
    type HashGadget = MiMCNonFeistelCRHGadget<Fr, MIMC_7_91_BN254_PARAMS>;

    #[test]
    fn correct_nearby() -> Result<(), Box<dyn Error>> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mimc = MiMC::<_, MIMC_7_91_BN254_PARAMS>::new(
            1,
            Fr::zero(),
            round_keys_contants_to_vec(&MIMC_7_91_BN254_ROUND_KEYS),
        );
        let mimc_var = MiMCVar::new_constant(cs.clone(), mimc.clone())?;
        let values = vec![
            Fr::from(1),
            Fr::from(2),
            Fr::from(3),
            Fr::from(4),
            Fr::from(5),
        ];
        let tree = RefCell::new(Tree::new_from_values(
            &values,
            None,
            mimc.clone(),
            mimc.clone(),
        ));

        let root_var = FpVar::new_input(cs.clone(), || Ok(tree.borrow().root))?;
        let tree_var = TreeVar::new(
            RefCell::clone(&tree),
            root_var,
            mimc_var.clone(),
            mimc_var.clone(),
        );

        let values_var = Vec::<FpVar<Fr>>::new_witness(cs.clone(), || Ok(values))?;
        let _is_contained = tree_var.contains(&values_var[0])?;

        //let root = tree.root;

        Ok(())
    }
}
