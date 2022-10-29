//! Sponge permutation / hash trait

use crate::{errors::PrimitivesError, poseidon::traits::PadSmallerChunk, rescue::RATE};
use ark_ff::PrimeField;
use ark_std::{string::ToString, vec::Vec, Zero};
use core::convert::TryInto;
use jf_utils::pad_with_zeros;

use super::{
    traits::{Extract, MdsPseudoRandomPermute, PermutationTrait, VectorOf, VectorT},
    ParameterHelper, PoseidonMatrix, PoseidonVector, ROUNDS, STATE_SIZE,
};

/// Instance of a Sponge cryptographic permutation to be used for instantiation
/// hashing, pseudo-random function, and other cryptographic primitives
pub struct SpongePermutation<F: PrimeField> {
    ///
    pub poseidon_prp: SpongePRPInstance<F>,
    ///
    pub round_keys: Vec<PoseidonVector<F>>,
    ///
    pub mds_matrix: PoseidonMatrix<F>,
}

/// Sponge Permutation trait
pub trait SpongePermutationT<F: PrimeField>: PermutationTrait<F> {
    /// Sponge permutation
    /// Sponge hashing based on poseidon permutation for Bls12_381 scalar field.
    /// allows unrestricted variable length
    /// input and number of output elements
    fn sponge_with_padding(&self, input: &[F], num_output: usize, rate: usize) -> Vec<F> {
        // Pad input as follows: append a One, then pad with 0 until length is multiple
        // of RATE
        let mut padded = input.to_vec();
        padded.push(F::one());
        pad_with_zeros(&mut padded, rate);
        self.sponge_no_padding(padded.as_slice(), num_output, rate)
            .expect("Bug in JF Primitives : bad padding of input for FSKS construction")
    }

    /// Sponge hashing based on poseidon permutation for Bls12_381 scalar field.
    /// allows input length multiple of the
    /// RATE and variable output length
    fn sponge_no_padding(
        &self,
        input: &[F],
        num_output: usize,
        rate: usize,
    ) -> Result<Vec<F>, PrimitivesError> {
        if input.len() % rate != 0 {
            return Err(PrimitivesError::ParameterError(
                "Rescue sponge Error : input to sponge hashing function is not multiple of RATE."
                    .to_string(),
            ));
        }
        // ABSORB PHASE
        let mut state = VectorOf::<F, Self>::zero();
        input.chunks_exact(rate).into_iter().for_each(|chunk| {
            let block = VectorOf::<F, Self>::pad_smaller_chunk(chunk);
            state.add_assign(&block);
            state = self.eval(&state)
        });

        // SQUEEZE PHASE
        let mut result = vec![];
        let mut remaining = num_output;
        // extract current rate before calling PRP again
        loop {
            let extract = remaining.min(rate);
            result.extend_from_slice(&state.extract(extract));
            remaining -= extract;
            if remaining == 0 {
                break;
            }
            state = self.eval(&state)
        }
        Ok(result)
    }
}

impl<F> PermutationTrait<F> for SpongePermutation<F>
where
    F: ParameterHelper,
{
    type PRP = SpongePRPInstance<F>;

    /// Return a pointer to the instance.
    /// Does not expose secret states.
    fn prp_ref(&self) -> &SpongePRPInstance<F> {
        &self.poseidon_prp
    }

    /// Return a pointer to the round key.
    /// Does not expose secret states.
    fn round_keys_ref(&self) -> &[PoseidonVector<F>] {
        &self.round_keys
    }

    /// Return a pointer to the mds matrix.
    /// Does not expose secret states.
    fn mds_matrix_ref(&self) -> &PoseidonMatrix<F> {
        &self.mds_matrix
    }
    /// Compute the permutation on PoseidonVector `input`
    fn eval(&self, input: &PoseidonVector<F>) -> PoseidonVector<F> {
        self.poseidon_prp
            .prp_with_round_keys(self.round_keys_ref(), input)
    }

    fn hash(
        &self,
        input: &[F],
        num_output: usize,
        rate: usize,
    ) -> Result<PoseidonVector<F>, PrimitivesError> {
        self.sponge_no_padding(input, num_output, rate)
            .map(|output| PoseidonVector::<F>::from_vec(output))
    }
}

// Implement Sponge Hashing
impl<F> SpongePermutationT<F> for SpongePermutation<F>
where
    F: ParameterHelper,
{
    /// Sponge hashing based on poseidon permutation for Bls12_381 scalar field
    /// for RATE 3 and CAPACITY 1. It allows unrestricted variable length
    /// input and number of output elements
    fn sponge_with_padding(&self, input: &[F], num_output: usize, rate: usize) -> Vec<F> {
        // Pad input as follows: append a One, then pad with 0 until length is multiple
        // of RATE
        let mut padded = input.to_vec();
        padded.push(F::one());
        pad_with_zeros(&mut padded, RATE);
        self.sponge_no_padding(padded.as_slice(), num_output, rate)
            .expect("Bug in JF Primitives : bad padding of input for FSKS construction")
    }

    /// Sponge hashing based on poseidon permutation for Bls12_381 scalar field
    /// for RATE 3 and CAPACITY 1. It allows input length multiple of the
    /// RATE and variable output length
    fn sponge_no_padding(
        &self,
        input: &[F],
        num_output: usize,
        rate: usize,
    ) -> Result<Vec<F>, PrimitivesError> {
        if input.len() % rate != 0 {
            return Err(PrimitivesError::ParameterError(
                "Rescue sponge Error : input to sponge hashing function is not multiple of RATE."
                    .to_string(),
            ));
        }
        // ABSORB PHASE
        let mut state = PoseidonVector::<F>::zero();
        input.chunks_exact(RATE).into_iter().for_each(|chunk| {
            let block = PoseidonVector::<F>::pad_smaller_chunk(chunk);
            state.add_assign(&block);
            state = self.eval(&state)
        });

        // SQUEEZE PHASE
        let mut result = vec![];
        let mut remaining = num_output;
        // extract current rate before calling PRP again
        loop {
            let extract = remaining.min(RATE);
            result.extend_from_slice(&state.extract(extract));
            remaining -= extract;
            if remaining == 0 {
                break;
            }
            state = self.eval(&state)
        }
        Ok(result)
    }
}

impl<F> Default for SpongePermutation<F>
where
    F: ParameterHelper,
{
    fn default() -> Self {
        SpongePRPInstance::<F>::default().into()
    }
}

impl<F> SpongePermutation<F>
where
    F: ParameterHelper,
{
    /// Pseudorandom function for Bls12_381 scalar field. It allows unrestricted
    /// variable length input and number of output elements
    pub fn full_state_keyed_sponge_with_padding(
        &self,
        key: &F,
        input: &[F],
        num_outputs: usize,
    ) -> Vec<F> {
        let mut padded_input = input.to_vec();
        padded_input.push(F::one());
        pad_with_zeros(&mut padded_input, STATE_SIZE);
        self.full_state_keyed_sponge_no_padding(key, padded_input.as_slice(), num_outputs)
            .expect("Bug in JF Primitives : bad padding of input for FSKS construction")
    }

    /// Pseudorandom function for Bls12_381 scalar field. It allows unrestricted
    /// variable length input and number of output elements. Return error if
    /// input is not multiple of STATE_SIZE = 4
    pub fn full_state_keyed_sponge_no_padding(
        &self,
        key: &F,
        input: &[F],
        num_outputs: usize,
    ) -> Result<Vec<F>, PrimitivesError> {
        if input.len() % STATE_SIZE != 0 {
            return Err(PrimitivesError::ParameterError(
                "Rescue FSKS PRF Error: input to prf function is not multiple of STATE_SIZE."
                    .to_string(),
            ));
        }
        // ABSORB PHASE
        let mut state = PoseidonVector::<F>::zero();
        state.set_index(STATE_SIZE - 1, *key);
        input.chunks_exact(STATE_SIZE).for_each(|chunk| {
            state.add_assign_elems(chunk);
            state = self.eval(&state);
        });
        // SQUEEZE PHASE
        let mut result = vec![];
        let mut remaining = num_outputs;
        // extract current rate before calling PRP again
        loop {
            let extract = remaining.min(RATE);
            result.extend_from_slice(&state.extract(extract));
            remaining -= extract;
            if remaining == 0 {
                break;
            }
            state = self.eval(&state)
        }
        Ok(result)
    }
}

impl<F> From<SpongePRPInstance<F>> for SpongePermutation<F>
where
    F: ParameterHelper,
{
    fn from(poseidon: SpongePRPInstance<F>) -> Self {
        let mut keys: Vec<PoseidonVector<F>> = Vec::with_capacity(2 * ROUNDS + 1);
        for key in F::PERMUTATION_ROUND_KEYS.iter() {
            keys.push(PoseidonVector::from_elems_le_bytes(
                key[0], key[1], key[2], key[3],
            ))
        }

        let matrix = PoseidonMatrix::from(&[
            PoseidonVector::from_elems_le_bytes(
                F::MDS_LE[0][0],
                F::MDS_LE[0][1],
                F::MDS_LE[0][2],
                F::MDS_LE[0][3],
            ),
            PoseidonVector::from_elems_le_bytes(
                F::MDS_LE[1][0],
                F::MDS_LE[1][1],
                F::MDS_LE[1][2],
                F::MDS_LE[1][3],
            ),
            PoseidonVector::from_elems_le_bytes(
                F::MDS_LE[2][0],
                F::MDS_LE[2][1],
                F::MDS_LE[2][2],
                F::MDS_LE[2][3],
            ),
            PoseidonVector::from_elems_le_bytes(
                F::MDS_LE[3][0],
                F::MDS_LE[3][1],
                F::MDS_LE[3][2],
                F::MDS_LE[3][3],
            ),
        ]);
        SpongePermutation {
            mds_matrix: matrix.try_into().unwrap(),
            poseidon_prp: poseidon,
            round_keys: keys,
        }
    }
}

// Rescue Pseudorandom Permutation (PRP) implementation for the BLS12_381 Scalar
// field with 4 elements as key and input size. From the PRP it derives 3 hash
// functions: 1. Sponge construction with arbitrary input and output length
// 2. Sponge construction with input length multiple of the RATE (3) (no padding
// needed) 3. 3 to 1 hashing (same construction as 1 and 2, but limiting the
// input to 3 and output to 1

#[derive(Clone)]
#[allow(clippy::upper_case_acronyms)]
/// Sponge pseudo-random permutation (PRP) instance
pub struct SpongePRPInstance<F> {
    /// Poseidon permutation MDS matrix
    pub mds: PoseidonMatrix<F>,
    /// Poseidon permutation initial constants
    pub init_vec: PoseidonVector<F>,
    /// Poseidon permutation key injection constants to compute round keys
    pub key_injection: Vec<PoseidonVector<F>>,
}

impl<F: ParameterHelper> Default for SpongePRPInstance<F> {
    fn default() -> Self {
        let mut key_injection = Vec::with_capacity(2 * ROUNDS);
        for bytes in F::KEY_INJECTION_LE.iter() {
            key_injection.push(PoseidonVector::from_elems_le_bytes(
                bytes[0], bytes[1], bytes[2], bytes[3],
            ));
        }
        SpongePRPInstance {
            mds: PoseidonMatrix::from(&[
                PoseidonVector::from_elems_le_bytes(
                    F::MDS_LE[0][0],
                    F::MDS_LE[0][1],
                    F::MDS_LE[0][2],
                    F::MDS_LE[0][3],
                ),
                PoseidonVector::from_elems_le_bytes(
                    F::MDS_LE[1][0],
                    F::MDS_LE[1][1],
                    F::MDS_LE[1][2],
                    F::MDS_LE[1][3],
                ),
                PoseidonVector::from_elems_le_bytes(
                    F::MDS_LE[2][0],
                    F::MDS_LE[2][1],
                    F::MDS_LE[2][2],
                    F::MDS_LE[2][3],
                ),
                PoseidonVector::from_elems_le_bytes(
                    F::MDS_LE[3][0],
                    F::MDS_LE[3][1],
                    F::MDS_LE[3][2],
                    F::MDS_LE[3][3],
                ),
            ]),
            init_vec: PoseidonVector::from_elems_le_bytes(
                F::INIT_VEC_LE[0],
                F::INIT_VEC_LE[1],
                F::INIT_VEC_LE[2],
                F::INIT_VEC_LE[3],
            ),
            key_injection,
        }
    }
}

impl<F: ParameterHelper> SpongePRPInstance<F> {
    /// Key scheduling for rescue based PRP for Bls12_381 scalars vector of size
    /// 4
    pub fn key_schedule(&self, key: &PoseidonVector<F>) -> Vec<PoseidonVector<F>> {
        let mut aux = key.add(&self.init_vec);
        let mut round_keys = vec![aux];
        (0..2 * ROUNDS).for_each(|i| {
            let exp = if (i % 2).is_zero() { F::A_INV } else { &[F::A] };
            aux.pow(exp);
            aux.linear(&self.mds.matrix.to_vec(), &self.key_injection[i]);
            println!("key injection: {:?}", self.key_injection[i]);
            round_keys.push(aux);
        });
        round_keys
    }
}

impl<F: ParameterHelper> MdsPseudoRandomPermute<F> for SpongePRPInstance<F> {
    type Vector = PoseidonVector<F>;
    /// Poseidon pseudorandom permutation for Bls12381 scalars vectors of size 4
    /// without key scheduled keys (scheduling occurs online)
    fn prp(&self, key: &PoseidonVector<F>, input: &PoseidonVector<F>) -> PoseidonVector<F> {
        let round_keys = self.key_schedule(key);
        self.prp_with_round_keys(round_keys.as_slice(), input)
    }

    /// Poseidon pseudorandom permutation for Bls12381 scalars vectors of size 4
    /// using scheduled keys
    fn prp_with_round_keys(
        &self,
        round_keys: &[PoseidonVector<F>],
        input: &PoseidonVector<F>,
    ) -> PoseidonVector<F> {
        assert_eq!(round_keys.len(), 2 * ROUNDS + 1);
        let mut perm_state = input.add(&round_keys[0]);
        round_keys[1..].iter().enumerate().for_each(|(round, key)| {
            if (round % 2).is_zero() {
                perm_state.pow(F::A_INV);
            } else {
                perm_state.pow(&[F::A]);
            }
            perm_state.linear(&self.mds.matrix.to_vec(), key)
        });
        perm_state
    }

    /// Return a pointer to the mds matrix.
    /// Does not expose secret states.
    fn mds_matrix_ref(&self) -> &PoseidonMatrix<F> {
        &self.mds
    }

    /// Return a pointer to the key injection vectors.
    /// Function needs to be public for circuits generation..
    /// WARNING!!! May expose secret state if keys are supposed to be secret.
    fn key_injection_vec_ref(&self) -> &[PoseidonVector<F>] {
        &self.key_injection
    }

    /// Return a pointer to the initial vectors.
    /// Does not expose secret states.
    fn init_vec_ref(&self) -> &PoseidonVector<F> {
        &self.init_vec
    }
}
