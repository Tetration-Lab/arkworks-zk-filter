use std::cell::RefCell;

use ark_crypto_primitives::{
    crh::{TwoToOneCRH, TwoToOneCRHGadget},
    CRHGadget, CRH,
};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{AllocVar, Boolean, EqGadget},
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
    pub fn contains(&self, leaf: &FpVar<F>) -> Result<Boolean<F>, SynthesisError> {
        let cs = self.root.cs();
        let tree = self.tree.borrow();
        let (index, hashed_leaf, proof) = match leaf.value() {
            Ok(value) => {
                let index = tree.leaf.binary_search(&value).unwrap_or(0);
                let mut proof_index = index;
                let hashed =
                    <H as CRH>::evaluate(&tree.param_crh, &value.into_repr().to_bytes_le())
                        .expect("Should able to hash");
                let mut proof = vec![];
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
                    tmp_leaf.push(hashed);
                    match index % 2 == 0 {
                        true => proof.push(tmp_leaf[proof_index + 1]),
                        false => proof.push(tmp_leaf[proof_index - 1]),
                    }
                    proof_index /= 2;
                }

                let hashed_var = FpVar::new_witness(ns!(cs, "proof: hashed"), || Ok(hashed))?;
                let proof_var = Vec::<FpVar<F>>::new_witness(ns!(cs, "proof: path"), || Ok(proof))?;

                (proof_index, hashed_var, proof_var)
            }
            Err(_) => {
                //MerkleTree;
                let hashed = FpVar::new_witness(ns!(cs, "proof: hashed"), || Ok(F::zero()))?;
                let proof = Vec::<FpVar<F>>::new_witness(ns!(cs, "proof: path"), || {
                    Ok(vec![F::zero(); HEIGHT - 2])
                })?;
                (0, hashed, proof)
            }
        };

        let calculated_hashed_leaf =
            <HG as CRHGadget<H, F>>::evaluate(&self.param_crh, &leaf.to_bytes()?)?;
        let (calculated_root, _) = proof.into_iter().try_fold(
            (calculated_hashed_leaf.clone(), index),
            |prev, next| -> Result<_, SynthesisError> {
                Ok((
                    match index % 2 == 0 {
                        true => <HG as TwoToOneCRHGadget<H, F>>::evaluate(
                            &self.param_tto_crh,
                            &prev.0.to_bytes()?,
                            &next.to_bytes()?,
                        ),
                        false => <HG as TwoToOneCRHGadget<H, F>>::evaluate(
                            &self.param_tto_crh,
                            &next.to_bytes()?,
                            &prev.0.to_bytes()?,
                        ),
                    }?,
                    index / 2,
                ))
            },
        )?;

        calculated_hashed_leaf
            .is_eq(&hashed_leaf)?
            .and(&calculated_root.is_eq(&self.root)?)
    }
}
