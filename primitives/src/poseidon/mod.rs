// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the Jellyfish library.

// You should have received a copy of the MIT License
// along with the Jellyfish library. If not, see <https://mit-license.org/>.

#![deny(missing_docs)]
//! This module implements Rescue hash function over the following fields
//! - bls12_377 base field
//! - ed_on_bls12_377 base field
//! - ed_on_bls12_381 base field
//! - ed_on_bn254 base field
//!
//! It also has place holders for
//! - bls12_381 base field
//! - bn254 base field
//! - bw6_761 base field
//!
//! Those three place holders should never be used.

#![deny(warnings)]
pub mod commitment;
pub mod errors;
mod poseidon_constants;
pub mod sponge;
pub mod traits;
pub mod vanilla;

#[cfg(test)]
pub mod tests;

use core::{convert::TryInto, ops::Add};

use ark_ff::PrimeField;
use ark_std::{vec::Vec, Zero};

use self::traits::{Extract, MatrixT, PadSmallerChunk, PermutationTrait, VectorT};

/// The state size of rescue hash.
pub const STATE_SIZE: usize = 4;
/// The rate of rescue hash.
pub const RATE: usize = 3;

/// The # of rounds of rescue hash.
// In the paper, to derive ROUND:
//  sage: m = 4
//  sage: for N in range (13):
//  ....:     t = m*N*3+3+2
//  ....:     b = m*N + 3
//  ....:     sec = factorial(t)/factorial(b)/factorial(t-b)
//  ....:     print (N, RR(log(sec^2,2)))
//
// for alpha = 5, (i.e., BLS12-381 and BN254)
//      10 224.672644456021
//      11 246.589942930803
//      12 268.516687541633
// set ROUND = 12, we have 134 bits security
//
// for alpha = 11, (i.e. BLS12-377) we have l1 =
//      7 227.364142668101
//      8 258.421493926570
//      9 289.491120346551
//      10 320.571247089962
//      11 351.660410749737
//      12 382.757409540148
// The smallest possible round number will be max(10, l1), which
// means round = 10 gives 160 bits security
//
// There is also the script from
//  https://github.com/EspressoSystems/Marvellous
//
// For unknown reasons, for all alpha >=5, the ROUND number is taken as if alpha
// = 5. This parameter choice does not seem to be optimal
//
//  if (self.alpha == 3):
//      self.Nb = max(10, 2*ceil((1.0 * security_level + 2) / (4*m)))
//  elif (self.alpha == 5):
//      self.Nb = max(10, 2*ceil((1.0 * security_level + 3) / (5.5*m)))
//  else :
//      self.Nb = max(10, 2*ceil((1.0 * security_level + 3) / (5.5*m)))
//  # where m = 4
//
// For conservative purpose, we are setting ROUNDS = 12 for now.
// We may consider to use ROUNDS = 10 for BLS12-377 (alpha = 11) in futures.
pub const ROUNDS: usize = 12;

/// The Sbox struct contains just a public signed 8-bit integer.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Sbox(pub i8);

/// This trait defines constants that are used for rescue hash functions.
pub trait ParameterHelper: PrimeField {
    /// parameter A, a.k.a., alpha
    const A: u64;

    /// RATE
    const RATE: usize = RATE;
    /// WIDTH = STATE_SIZE + 1
    const WIDTH: u32 = 0;
    /// PARTIAL_ROUNDS
    const PARTIAL_ROUNDS: u32 = 0;
    /// FULL_ROUNDS
    const FULL_ROUNDS: u32 = 0;

    /// parameter A^-1
    const A_INV: &'static [u64];
    /// MDS matrix
    const MDS_LE: [[&'static [u8]; STATE_SIZE]; STATE_SIZE];
    /// Initial vector.
    const INIT_VEC_LE: [&'static [u8]; STATE_SIZE];
    /// Injected keys for each round.
    const KEY_INJECTION_LE: [[&'static [u8]; 4]; 2 * ROUNDS];
    /// Permutation keys.
    const PERMUTATION_ROUND_KEYS: [[&'static [u8]; 4]; 25];

    /// Partial rounds from Poseidon permutation.
    fn partial_rounds() -> usize {
        Self::PARTIAL_ROUNDS as usize
    }

    /// Full rounds from Poseidon permutation
    fn full_rounds() -> usize {
        Self::FULL_ROUNDS as usize
    }

    /// Chosen sbox / exponentiation
    fn sbox() -> Sbox {
        Sbox(-1)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Copy)]
/// Data type for rescue prp inputs, keys and internal data
pub struct PoseidonVector<F> {
    pub(crate) vec: [F; STATE_SIZE],
}

impl<F: PrimeField> Default for PoseidonVector<F> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<F: ParameterHelper> VectorT<F> for PoseidonVector<F> {
    fn len(&self) -> usize {
        self.vec.len()
    }

    fn set_index(&mut self, index: usize, value: F) {
        assert!(index < self.len());
        self.vec[index] = value;
    }

    fn into_vec(&self) -> Vec<F> {
        self.vec.to_vec()
    }

    fn from_vec(v: Vec<F>) -> Self {
        Self {
            vec: v.try_into().unwrap(),
        }
    }

    /// Return vector of the field elements
    /// WARNING: may expose the internal state.
    fn elems(&self) -> Vec<F> {
        self.into_vec()
    }

    /// Helper function to compute f(M,x,c) = Mx^a + c.
    /// Function needs to be public for circuits generation..
    fn non_linear(&mut self, matrix: &[PoseidonVector<F>], vector: &PoseidonVector<F>) {
        let matrix: PoseidonMatrix<F> = PoseidonMatrix {
            matrix: matrix.try_into().unwrap(),
        };
        let mut self_aux = *self;
        self_aux.pow(&[F::A]);
        let mut aux = matrix.mul_vec(&self_aux);
        aux.add_assign(vector);
        *self = aux;
    }

    /// Perform a linear transform of the vector.
    /// Function needs to be public for circuits generation..
    fn linear(&mut self, matrix: &[PoseidonVector<F>], vector: &PoseidonVector<F>) {
        let matrix: PoseidonMatrix<F> = PoseidonMatrix {
            matrix: matrix.try_into().unwrap(),
        };
        let mut aux = matrix.mul_vec(self);
        aux.add_assign(vector);
        *self = aux
    }

    fn pow(&mut self, exp: &[u64]) {
        self.vec.iter_mut().for_each(|elem| {
            *elem = elem.pow(exp);
        });
    }

    fn add_assign(&mut self, vector: &PoseidonVector<F>) {
        for (a, b) in self.vec.iter_mut().zip(vector.vec.iter()) {
            a.add_assign(b);
        }
    }

    fn add(&self, vector: &PoseidonVector<F>) -> PoseidonVector<F> {
        let mut aux = *self;
        aux.add_assign(vector);
        aux
    }

    fn add_assign_elems(&mut self, elems: &[F]) {
        assert_eq!(elems.len(), STATE_SIZE);
        self.vec
            .iter_mut()
            .zip(elems.iter())
            .for_each(|(a, b)| a.add_assign(b));
    }

    fn dot_product(&self, vector: &PoseidonVector<F>) -> F {
        let mut r = F::zero();
        for (a, b) in self.vec.iter().zip(vector.vec.iter()) {
            r.add_assign(&a.mul(b));
        }
        r
    }
}

impl<F: PrimeField> Extract<F> for PoseidonVector<F> {
    fn extract(&self, extract: usize) -> &[F] {
        &self.vec[0..extract]
    }
}

impl<F: PrimeField> PadSmallerChunk<F> for PoseidonVector<F> {
    fn pad_smaller_chunk(input: &[F]) -> Self {
        assert!(input.len() < 4);
        let mut vec = Self::zero().vec;
        for (i, elem) in input.iter().enumerate() {
            vec[i] = *elem;
        }
        Self { vec }
    }
}

impl<F: PrimeField> Add for PoseidonVector<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        let mut res = PoseidonVector::zero();
        for i in 0..STATE_SIZE {
            res.vec[i] = self.vec[i] + rhs.vec[i];
        }
        res
    }
}

impl<F: PrimeField> Zero for PoseidonVector<F> {
    /// zero vector
    fn zero() -> PoseidonVector<F> {
        PoseidonVector {
            vec: [F::zero(); STATE_SIZE],
        }
    }

    fn is_zero(&self) -> bool {
        for i in 0..STATE_SIZE {
            if !self.vec[i].is_zero() {
                return false;
            }
        }
        true
    }
}

// Private functions
impl<F: PrimeField> PoseidonVector<F> {
    fn from_elems_le_bytes(e0: &[u8], e1: &[u8], e2: &[u8], e3: &[u8]) -> PoseidonVector<F> {
        PoseidonVector {
            vec: [
                F::from_le_bytes_mod_order(e0),
                F::from_le_bytes_mod_order(e1),
                F::from_le_bytes_mod_order(e2),
                F::from_le_bytes_mod_order(e3),
            ],
        }
    }
}

impl<F: Copy> From<&[F]> for PoseidonVector<F> {
    fn from(field_elems: &[F]) -> PoseidonVector<F> {
        assert_eq!(field_elems.len(), STATE_SIZE);
        PoseidonVector {
            vec: [
                field_elems[0],
                field_elems[1],
                field_elems[2],
                field_elems[3],
            ],
        }
    }
}

impl<F: Copy> From<&[F; STATE_SIZE]> for PoseidonVector<F> {
    fn from(field_elems: &[F; STATE_SIZE]) -> PoseidonVector<F> {
        PoseidonVector { vec: *field_elems }
    }
}

/// A matrix that consists of `STATE_SIZE` number of rescue vectors.
#[derive(Clone)]
pub struct PoseidonMatrix<F> {
    matrix: [PoseidonVector<F>; STATE_SIZE],
}

impl<F: PrimeField> From<&[PoseidonVector<F>; STATE_SIZE]> for PoseidonMatrix<F> {
    fn from(vectors: &[PoseidonVector<F>; STATE_SIZE]) -> Self {
        Self { matrix: *vectors }
    }
}

impl<F: ParameterHelper> MatrixT<F> for PoseidonMatrix<F> {
    type Vector = PoseidonVector<F>;

    fn mul_vec(&self, vector: &PoseidonVector<F>) -> PoseidonVector<F> {
        let mut result = [F::zero(); STATE_SIZE];
        self.matrix
            .iter()
            .enumerate()
            .for_each(|(i, row)| result[i] = row.dot_product(vector));
        PoseidonVector { vec: result }
    }

    /// Accessing the i-th vector of the matrix.    
    /// Function needs to be public for circuits generation..
    /// WARNING: may expose the internal state.
    fn vec(&self, i: usize) -> PoseidonVector<F> {
        self.matrix[i]
    }

    /// Check if the matrix is empty.
    fn is_empty(&self) -> bool {
        self.matrix.is_empty()
    }

    /// Return the number of columns of the matrix.
    fn len(&self) -> usize {
        self.matrix.len()
    }

    fn to_vec(&self) -> Vec<PoseidonVector<F>> {
        self.matrix.to_vec()
    }
}
