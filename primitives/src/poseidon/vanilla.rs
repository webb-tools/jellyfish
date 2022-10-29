//! Poseidon permutation / hash trait.

use super::{traits::PermutationTrait, ParameterHelper};
use crate::{
    errors::PrimitivesError,
    poseidon::traits::{VectorOf, VectorT},
};
use ark_std::{string::ToString, vec::Vec, Zero};

/// OG Poseidon style permutation (no sponge)
pub trait PoseidonPermutation<F: ParameterHelper>: PermutationTrait<F> {
    /// Direct permutation
    /// Direct hashing based on poseidon permutation for Bls12_381 scalar field.
    /// It allows input length multiple of the
    /// RATE and variable output length
    fn direct_no_padding(&self, input: &[F], width: usize) -> Result<Vec<F>, PrimitivesError> {
        // Populate a state vector with 0 and then inputs, pad with zeros if necessary
        if input.len() > width - 1 {
            return Err(PrimitivesError::ParameterError(
                "Poseidon direct Error : input to direct hashing function is too long.".to_string(),
            ));
        }
        let mut state = <VectorOf<F, Self>>::zero();
        assert!(state.len() == width);
        for (inx, f) in input.iter().enumerate() {
            state.set_index(inx + 1, *f);
        }

        self.eval(&state);

        Ok(state.into_vec())
    }
}
