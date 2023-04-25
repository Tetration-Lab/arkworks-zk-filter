use ark_crypto_primitives::{crh::TwoToOneCRH, CRH};
use ark_ff::{BigInteger, PrimeField};

pub struct SortedMerkleTree<
    const HEIGHT: usize,
    F: PrimeField,
    H: CRH<Output = F> + TwoToOneCRH<Output = F>,
> {
    pub root: F,
    pub leaf: Vec<F>,
    pub hashed_empty_leaf: F,
    pub param_crh: <H as CRH>::Parameters,
    pub param_tto_crh: <H as TwoToOneCRH>::Parameters,
}

impl<const HEIGHT: usize, F: PrimeField, H: CRH<Output = F> + TwoToOneCRH<Output = F>>
    SortedMerkleTree<HEIGHT, F, H>
{
    fn calculate_root(leaf: &[F], param_tto_crh: &<H as TwoToOneCRH>::Parameters) -> F {
        assert!(leaf.len() == 1 << (HEIGHT - 1), "Invalid leaf length");
        let mut tmp_leaf = leaf.to_vec();
        while tmp_leaf.len() > 1 {
            tmp_leaf = tmp_leaf
                .chunks(2)
                .map(|chunk| {
                    let left = chunk[0];
                    let right = chunk[1];
                    <H as TwoToOneCRH>::evaluate(
                        &param_tto_crh,
                        &left.into_repr().to_bytes_le(),
                        &right.into_repr().to_bytes_le(),
                    )
                    .expect("Should able to hash")
                })
                .collect::<Vec<_>>();
        }
        tmp_leaf[0]
    }

    pub fn empty(
        empty_leaf: Option<F>,
        param_crh: <H as CRH>::Parameters,
        param_tto_crh: <H as TwoToOneCRH>::Parameters,
    ) -> Self {
        let hashed_empty_leaf = <H as CRH>::evaluate(
            &param_crh,
            &empty_leaf.unwrap_or_default().into_repr().to_bytes_le(),
        )
        .expect("Should able to hash");
        let leaf = vec![hashed_empty_leaf; 1 << (HEIGHT - 1)];
        let root = Self::calculate_root(&leaf, &param_tto_crh);

        Self {
            root,
            leaf,
            hashed_empty_leaf,
            param_crh,
            param_tto_crh,
        }
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::Zero;
    use arkworks_mimc::{
        params::{
            mimc_7_91_bn254::{MIMC_7_91_BN254_PARAMS, MIMC_7_91_BN254_ROUND_KEYS},
            round_keys_contants_to_vec,
        },
        MiMC, MiMCNonFeistelCRH,
    };

    use super::SortedMerkleTree;

    type Tree = SortedMerkleTree<5, Fr, Hash>;
    type Hash = MiMCNonFeistelCRH<Fr, MIMC_7_91_BN254_PARAMS>;

    #[test]
    fn correct_empty_tree() {
        let mimc = MiMC::<_, MIMC_7_91_BN254_PARAMS>::new(
            1,
            Fr::zero(),
            round_keys_contants_to_vec(&MIMC_7_91_BN254_ROUND_KEYS),
        );
        let _ = Tree::empty(None, mimc.clone(), mimc.clone());
    }
}
