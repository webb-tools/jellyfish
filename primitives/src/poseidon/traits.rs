// Copyright (c) 2022 Webb Technologies (webb.tools)
// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

//! Traits for generalizing hash functions and schemes

use ark_ff::PrimeField;
use ark_std::{vec::Vec, Zero};

use crate::errors::PrimitivesError;

use super::{PoseidonMatrix, PoseidonVector};

/// A trait generalizing commit/verify schemes.
pub trait CommitVerify<F: PrimeField> {
    /// Generate a new scheme
    fn new(input_len: usize) -> Self;
    /// Commit to `input` slice using blinding `blind`
    fn commit(&self, input: &[F], blind: &F) -> Result<F, PrimitivesError>;
    /// Verify `commitment` against `input` and `blind`
    fn verify(&self, input: &[F], blind: &F, commitment: &F) -> Result<(), PrimitivesError>;
}

///
pub trait Extract<F: PrimeField> {
    ///
    fn extract(&self, extract: usize) -> &[F];
}

///
pub trait PadSmallerChunk<F: PrimeField> {
    ///
    fn pad_smaller_chunk(chunk: &[F]) -> Self;
}

///
pub trait VectorT<F: PrimeField>:
    Extract<F> + PadSmallerChunk<F> + Zero + Clone + Default + PartialEq + Eq + Sized
{
    ///
    fn len(&self) -> usize;
    ///
    fn set_index(&mut self, index: usize, value: F);
    ///
    fn into_vec(&self) -> Vec<F>;
    ///
    fn from_vec(vec: Vec<F>) -> Self;
    ///
    fn elems(&self) -> Vec<F>;
    ///
    fn linear(&mut self, matrix: &[Self], vector: &Self);
    ///
    fn non_linear(&mut self, matrix: &[Self], vector: &Self);
    ///
    fn pow(&mut self, exp: &[u64]);
    ///
    fn add_assign(&mut self, vector: &Self);
    ///
    fn add(&self, vector: &Self) -> Self;
    ///
    fn add_assign_elems(&mut self, elems: &[F]);
    ///
    fn dot_product(&self, vector: &Self) -> F;
}

///
pub trait MatrixT<F: PrimeField> {
    ///
    type Vector: VectorT<F>;

    ///
    fn mul_vec(&self, vector: &PoseidonVector<F>) -> PoseidonVector<F>;
    ///
    fn vec(&self, i: usize) -> PoseidonVector<F>;
    ///
    fn is_empty(&self) -> bool;
    ///
    fn len(&self) -> usize;
    ///
    fn to_vec(&self) -> Vec<PoseidonVector<F>>;
}

/// A trait generalizing a Pseudon random permutation.
pub trait MdsPseudoRandomPermute<F: PrimeField>: Default {
    /// The Vector type for this prp.
    type Vector: VectorT<F>;
    /// MDS pseudorandom permutation for scalar vectors
    /// without key scheduled keys (scheduling occurs online)
    fn prp(&self, key: &Self::Vector, input: &Self::Vector) -> Self::Vector;
    /// MDS pseudorandom permutation for scalar vectors
    /// using scheduled keys
    fn prp_with_round_keys(
        &self,
        round_keys: &[Self::Vector],
        input: &Self::Vector,
    ) -> Self::Vector;
    /// Return a pointer to the mds matrix.
    /// Does not expose secret states.
    fn mds_matrix_ref(&self) -> &PoseidonMatrix<F>;

    /// Return a pointer to the key injection vectors.
    /// Function needs to be public for circuits generation..
    /// WARNING!!! May expose secret state if keys are supposed to be secret.
    fn key_injection_vec_ref(&self) -> &[PoseidonVector<F>];

    /// Return a pointer to the initial vectors.
    /// Does not expose secret states.
    fn init_vec_ref(&self) -> &PoseidonVector<F>;
}

///
#[allow(type_alias_bounds)]
pub type VectorOf<F: PrimeField, P: PermutationTrait<F>> =
    <<P as PermutationTrait<F>>::PRP as MdsPseudoRandomPermute<F>>::Vector;

///
#[allow(type_alias_bounds)]

/// A trait generalizing a permutation hash.
pub trait PermutationTrait<F: PrimeField>: Default {
    /// PRP type
    type PRP: MdsPseudoRandomPermute<F>;
    /// Return a pointer to the round key.
    /// Does not expose secret states.
    fn round_keys_ref(&self) -> &[VectorOf<F, Self>];
    /// Return a pointer to the PRP.
    /// Does not expose secret states.
    fn prp_ref(&self) -> &Self::PRP;
    /// Return a pointer to the mds matrix.
    /// Does not expose secret states.
    fn mds_matrix_ref(&self) -> &PoseidonMatrix<F>;
    /// Compute the permutation on Output type `input`
    fn eval(&self, input: &VectorOf<F, Self>) -> VectorOf<F, Self> {
        self.prp_ref()
            .prp_with_round_keys(self.round_keys_ref(), input)
            .into()
    }
    /// hash (mocks the eventual function used)
    fn hash(
        &self,
        input: &[F],
        num_output: usize,
        rate: usize,
    ) -> Result<VectorOf<F, Self>, PrimitivesError>;
}
