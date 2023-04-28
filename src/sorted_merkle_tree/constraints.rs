use std::cell::RefCell;

use ark_crypto_primitives::{
    crh::{TwoToOneCRH, TwoToOneCRHGadget},
    CRHGadget, CRH,
};
use ark_ff::{BigInteger, FpParameters, PrimeField};
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, Boolean, FieldVar},
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
        let (index, nearby, path) = match value.value() {
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
                                F::from_repr(<<F as PrimeField>::Params as FpParameters>::MODULUS)
                                    .expect("Should convert from modulus"),
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
                            (
                                F::zero(),
                                F::from_repr(<<F as PrimeField>::Params as FpParameters>::MODULUS)
                                    .expect("Should convert from modulus"),
                            ),
                            (None, None),
                            (vec![F::zero(); HEIGHT - 2], vec![F::zero(); HEIGHT - 2]),
                        ),
                    },
                    Err(_) => (
                        (
                            F::zero(),
                            F::from_repr(<<F as PrimeField>::Params as FpParameters>::MODULUS)
                                .expect("Should convert from modulus"),
                        ),
                        (None, None),
                        (vec![F::zero(); HEIGHT - 2], vec![F::zero(); HEIGHT - 2]),
                    ),
                };

                match index {
                    (None, None) => todo!(),
                    _ => {
                        let mut tmp_leaf = tree.leaf.to_vec();
                        while tmp_leaf.len() > 1 {
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

                            if let Some(i) = &mut index.0 {
                                proof.0.push(tmp_leaf[*i + 1]);
                                *i /= 2;
                            }

                            if let Some(i) = &mut index.1 {
                                proof.1.push(tmp_leaf[*i + 1]);
                                *i /= 2;
                            }
                        }
                    }
                };

                let left_hashed_var =
                    FpVar::new_witness(ns!(cs, "proof: left hash"), || Ok(nearby.0))?;
                let left_proof_var =
                    Vec::<FpVar<F>>::new_witness(ns!(cs, "proof: left path"), || Ok(proof.0))?;
                let right_hashed_var =
                    FpVar::new_witness(ns!(cs, "proof: right hash"), || Ok(nearby.1))?;
                let right_proof_var =
                    Vec::<FpVar<F>>::new_witness(ns!(cs, "proof: right path"), || Ok(proof.1))?;

                (
                    index,
                    (left_hashed_var, right_hashed_var),
                    (left_proof_var, right_proof_var),
                )
                //let hashed_var = FpVar::new_witness(ns!(cs, "proof: hashed"), || Ok(hashed))?;
                //let proof_var = Vec::<FpVar<F>>::new_witness(ns!(cs, "proof: path"), || Ok(proof))?;

                //(proof_index, hashed_var, proof_var)
            }
            Err(_) => {
                //MerkleTree;
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
                ((None, None), nearby, proof)
            }
        };

        let min = FpVar::constant(F::zero());
        let max = FpVar::constant(
            F::from_repr(<<F as PrimeField>::Params as FpParameters>::MODULUS)
                .expect("Should convert from modulus"),
        );

        let calculated_hashed_leaf =
            <HG as CRHGadget<H, F>>::evaluate(&self.param_crh, &value.to_bytes()?)?;
        //let is_not_nearby = calculated_hashed_leaf
        //.is_cmp(&proof.1 .0, Ordering::Greater, false)?
        //.and(&calculated_hashed_leaf.is_cmp(&proof.1 .0, Ordering::Less, false)?)?;
        let (_, calculated_root) = path.0.iter().zip(path.1.iter()).try_fold(
            (
                (index.0.unwrap_or_default(), index.1.unwrap_or_default()),
                nearby.clone(),
            ),
            |((left_ind, right_ind), (prev_left, prev_right)),
             (next_left, next_right)|
             -> Result<_, SynthesisError> {
                let left = match left_ind % 2 == 0 {
                    true => <HG as TwoToOneCRHGadget<H, F>>::evaluate(
                        &self.param_tto_crh,
                        &prev_left.to_bytes()?,
                        &next_left.to_bytes()?,
                    )?,
                    false => <HG as TwoToOneCRHGadget<H, F>>::evaluate(
                        &self.param_tto_crh,
                        &next_left.to_bytes()?,
                        &prev_left.to_bytes()?,
                    )?,
                };
                let right = match right_ind % 2 == 0 {
                    true => <HG as TwoToOneCRHGadget<H, F>>::evaluate(
                        &self.param_tto_crh,
                        &prev_right.to_bytes()?,
                        &next_right.to_bytes()?,
                    )?,
                    false => <HG as TwoToOneCRHGadget<H, F>>::evaluate(
                        &self.param_tto_crh,
                        &next_right.to_bytes()?,
                        &prev_right.to_bytes()?,
                    )?,
                };
                Ok(((left_ind / 2, right_ind / 2), (left, right)))
            },
        )?;
        //calculated_hashed_leaf
        //.is_cmp(&nearby.0, Ordering::Greater, false)?
        //.and(&nearby.0.is_eq(&min)?.or(other));
        //let is_included_nearby = calculated_hashed_leaf.is_eq(&proof.1 .0)?;
        //let (calculated_root, _) = proof.into_iter().try_fold(
        //(calculated_hashed_leaf.clone(), index),
        //|prev, next| -> Result<_, SynthesisError> {
        //Ok((
        //match index % 2 == 0 {
        //true => <HG as TwoToOneCRHGadget<H, F>>::evaluate(
        //&self.param_tto_crh,
        //&prev.0.to_bytes()?,
        //&next.to_bytes()?,
        //),
        //false => <HG as TwoToOneCRHGadget<H, F>>::evaluate(
        //&self.param_tto_crh,
        //&next.to_bytes()?,
        //&prev.0.to_bytes()?,
        //),
        //}?,
        //index / 2,
        //))
        //},
        //)?;

        //calculated_hashed_leaf
        //.is_eq(&hashed_leaf)?
        //.and(&calculated_root.is_eq(&self.root)?)
        Ok(Boolean::FALSE)
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, error::Error, rc::Rc};

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
        let is_contained = tree_var.contains(&values_var[0])?;

        //let root = tree.root;

        Ok(())
    }
}
