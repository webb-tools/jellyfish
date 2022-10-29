#[cfg(test)]
mod test_prp {
    use crate::poseidon::{
        sponge::SpongePRPInstance, traits::MdsPseudoRandomPermute, PoseidonVector,
    };
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as Fr377;
    use ark_ed_on_bls12_381::Fq as Fr381;
    use ark_ed_on_bn254::Fq as Fr254;
    use ark_ff::Zero;

    // hash output on vector [0, 0, 0, 0]
    // this value is cross checked with sage script
    // rescue761.Sponge([0,0,0,0], 4)
    const OUTPUT761: [[u8; 48]; 4] = [
        [
            0x37, 0xBE, 0x12, 0x7E, 0xDF, 0x9C, 0xBF, 0xCE, 0x78, 0xE1, 0x4F, 0xEB, 0x69, 0xAC,
            0x89, 0x53, 0xE7, 0xC4, 0x8D, 0x89, 0x90, 0x77, 0x64, 0x0D, 0xD0, 0x87, 0x42, 0xDD,
            0x1F, 0x98, 0x30, 0xC8, 0x0F, 0x12, 0x6D, 0x7A, 0x49, 0xD3, 0x22, 0x2E, 0x12, 0xBA,
            0x5B, 0x0E, 0x29, 0xB7, 0x2C, 0x01,
        ],
        [
            0x68, 0xFE, 0x2E, 0x95, 0x57, 0xDA, 0x2E, 0x36, 0xEC, 0xC1, 0xC5, 0x8A, 0x19, 0x50,
            0xD7, 0xBE, 0x11, 0x00, 0x3D, 0x5B, 0xAA, 0x8C, 0xF8, 0x45, 0x6F, 0xDC, 0xE4, 0x1F,
            0xF0, 0x35, 0xC7, 0x62, 0x6A, 0xC2, 0x33, 0xE7, 0x98, 0x9F, 0x26, 0x2A, 0x6E, 0x89,
            0xD5, 0x43, 0x21, 0xF8, 0x67, 0x01,
        ],
        [
            0x84, 0xB4, 0x93, 0x04, 0x3B, 0x23, 0x3A, 0x1B, 0x43, 0xC3, 0x61, 0x61, 0x1B, 0xA0,
            0x59, 0xFB, 0x2E, 0x88, 0x76, 0x62, 0x28, 0xBB, 0x32, 0x6F, 0x27, 0x1C, 0xA9, 0xCA,
            0x60, 0xC1, 0xE0, 0x7A, 0x7D, 0x37, 0x2F, 0x95, 0x75, 0xDD, 0x37, 0x2A, 0x70, 0xD1,
            0xE4, 0x55, 0xDB, 0x50, 0x2F, 0x00,
        ],
        [
            0x4E, 0x01, 0x9E, 0x8A, 0x7F, 0x6F, 0x3B, 0xDE, 0x7F, 0xF5, 0x58, 0x0B, 0x1A, 0x34,
            0x95, 0x8D, 0xBC, 0x94, 0x88, 0xD8, 0x5D, 0x25, 0x7A, 0xB0, 0xCC, 0x72, 0xFE, 0x36,
            0xC3, 0x13, 0xCB, 0x1B, 0x7A, 0x69, 0xCF, 0xCC, 0xAB, 0x2B, 0x55, 0x11, 0x1E, 0xC5,
            0x7C, 0xFC, 0x47, 0x7D, 0x9D, 0x01,
        ],
    ];

    // hash output on vector [0, 0, 0, 0]
    // this value is cross checked with sage script
    // rescue381.Sponge([0,0,0,0], 4)
    const OUTPUT381: [[u8; 32]; 4] = [
        [
            0x12, 0x53, 0x24, 0x66, 0x84, 0xA2, 0x4D, 0x2B, 0xC7, 0x28, 0x3E, 0x0F, 0x80, 0xDF,
            0x1A, 0xC3, 0x5B, 0xA1, 0xA9, 0x5B, 0x46, 0x60, 0xBD, 0xED, 0xA6, 0xD1, 0x43, 0xB7,
            0x60, 0xCA, 0x59, 0x0D,
        ],
        [
            0x1B, 0xBE, 0xAB, 0x6C, 0xAB, 0x62, 0xB7, 0xAB, 0x19, 0xDF, 0xFF, 0x4D, 0x73, 0xB5,
            0x78, 0x30, 0x72, 0xC0, 0xC6, 0xDA, 0x1F, 0x10, 0xAD, 0xD1, 0x28, 0x65, 0xB4, 0x94,
            0x6F, 0xAC, 0xE5, 0x4B,
        ],
        [
            0x07, 0x86, 0xBD, 0x9A, 0xB3, 0x35, 0x96, 0x22, 0xF0, 0xE5, 0xEA, 0xCC, 0x9C, 0x79,
            0x89, 0x1F, 0x9D, 0x1D, 0x43, 0x44, 0xCC, 0xA9, 0x9A, 0xB0, 0x0E, 0xC0, 0x57, 0x6B,
            0x07, 0xF8, 0x53, 0x06,
        ],
        [
            0x9C, 0x23, 0x34, 0xB3, 0x0A, 0xCD, 0x94, 0x11, 0x49, 0xC0, 0x9D, 0x90, 0x7E, 0x7E,
            0xC8, 0x51, 0x42, 0xD3, 0xCD, 0x5D, 0x05, 0x13, 0x31, 0x66, 0x4D, 0x36, 0x98, 0xCE,
            0xAC, 0x44, 0x5C, 0x60,
        ],
    ];
    // this value is cross checked with sage script
    // rescue377.Sponge([0,0,0,0], 4)
    const OUTPUT377: [[u8; 32]; 4] = [
        [
            0x65, 0xF2, 0xF2, 0x74, 0x15, 0x7A, 0x5A, 0xB5, 0xE0, 0x86, 0x46, 0x9D, 0xAE, 0x27,
            0x29, 0xE0, 0x08, 0x39, 0x0D, 0xA6, 0x44, 0x5E, 0x20, 0x76, 0x23, 0x42, 0xDA, 0xF0,
            0x49, 0xA3, 0x51, 0x02,
        ],
        [
            0x67, 0xB5, 0x6A, 0xBA, 0x4B, 0xB8, 0x0F, 0xE2, 0xFC, 0x3D, 0x7E, 0xFC, 0x70, 0xCA,
            0x3D, 0x1D, 0xAC, 0xDD, 0xEA, 0x62, 0x81, 0xD7, 0x08, 0x0B, 0x38, 0x5F, 0x0A, 0x68,
            0xEC, 0xED, 0x53, 0x02,
        ],
        [
            0x10, 0xC5, 0xA0, 0xA1, 0x8E, 0x8D, 0xBC, 0xAD, 0x99, 0xC3, 0xB4, 0xE9, 0x22, 0xC9,
            0xB1, 0xCF, 0x35, 0x46, 0xE3, 0x52, 0x99, 0x5B, 0xBE, 0x6E, 0x08, 0xFF, 0x4B, 0x2F,
            0xCE, 0xF0, 0xCB, 0x0A,
        ],
        [
            0x33, 0xB0, 0xD0, 0x58, 0xE9, 0x25, 0x15, 0xB2, 0x8A, 0x9D, 0x16, 0x04, 0xEB, 0x26,
            0xC4, 0x0E, 0x3F, 0xBF, 0xCF, 0x49, 0x20, 0xA8, 0x89, 0xE2, 0x16, 0x2D, 0x76, 0x19,
            0xDF, 0x01, 0x02, 0x09,
        ],
    ];

    // this value is cross checked with sage script
    // rescue254.Sponge([0,0,0,0], 4)
    const OUTPUT254: [[u8; 32]; 4] = [
        [
            0xDD, 0xE7, 0x55, 0x8E, 0x14, 0xF9, 0x4C, 0xEE, 0x9F, 0xCC, 0xB2, 0x02, 0xFC, 0x0E,
            0x54, 0x21, 0xF2, 0xAA, 0xB8, 0x48, 0x05, 0xDB, 0x9B, 0x7A, 0xD2, 0x36, 0xA5, 0xF1,
            0x49, 0x77, 0xB4, 0x17,
        ],
        [
            0x43, 0x5F, 0x99, 0x3C, 0xB7, 0xB3, 0x84, 0x74, 0x4E, 0x80, 0x83, 0xFF, 0x73, 0x20,
            0x07, 0xD9, 0x7B, 0xEC, 0x4B, 0x90, 0x48, 0x1D, 0xFD, 0x72, 0x4C, 0xF0, 0xA5, 0x7C,
            0xDC, 0x68, 0xC0, 0x25,
        ],
        [
            0x2C, 0x7B, 0x21, 0x09, 0x9D, 0x10, 0xE9, 0x5C, 0x36, 0x3E, 0x6D, 0x20, 0x28, 0xBB,
            0xDB, 0x1E, 0xED, 0xF4, 0x22, 0x9B, 0x3A, 0xEE, 0x1E, 0x6F, 0x89, 0x13, 0x3D, 0x1E,
            0x4C, 0xA0, 0xA6, 0x23,
        ],
        [
            0x25, 0x9B, 0x47, 0xA2, 0x29, 0xFD, 0xC1, 0x08, 0xA9, 0xD1, 0x44, 0x71, 0x15, 0x8A,
            0x5A, 0x1A, 0x55, 0x5B, 0x88, 0xAE, 0xD6, 0xF6, 0x57, 0xD3, 0x33, 0x07, 0xE1, 0x5B,
            0x71, 0x5F, 0x12, 0x25,
        ],
    ];

    #[test]
    fn test_poseidon_perm_on_0_vec() {
        test_poseidon_perm_on_0_vec_254();
        test_poseidon_perm_on_0_vec_377();
        test_poseidon_perm_on_0_vec_381();
        test_poseidon_perm_on_0_vec_761();
    }

    fn test_poseidon_perm_on_0_vec_254() {
        let poseidon = SpongePRPInstance::<Fr254>::default();
        let key = PoseidonVector::zero();
        let input = PoseidonVector::zero();
        let expected = PoseidonVector::from_elems_le_bytes(
            &OUTPUT254[0],
            &OUTPUT254[1],
            &OUTPUT254[2],
            &OUTPUT254[3],
        );
        let real_output = poseidon.prp(&key, &input);
        let round_keys = poseidon.key_schedule(&key);
        let real_output_with_round_keys = poseidon.prp_with_round_keys(&round_keys, &input);
        assert_eq!(real_output, real_output_with_round_keys);
        assert_eq!(real_output, expected);
    }

    fn test_poseidon_perm_on_0_vec_381() {
        let poseidon = SpongePRPInstance::<Fr381>::default();
        let key = PoseidonVector::zero();
        let input = PoseidonVector::zero();
        let expected = PoseidonVector::from_elems_le_bytes(
            &OUTPUT381[0],
            &OUTPUT381[1],
            &OUTPUT381[2],
            &OUTPUT381[3],
        );
        let real_output = poseidon.prp(&key, &input);
        let round_keys = poseidon.key_schedule(&key);
        let real_output_with_round_keys = poseidon.prp_with_round_keys(&round_keys, &input);

        assert_eq!(real_output, real_output_with_round_keys);
        assert_eq!(real_output, expected);
    }

    fn test_poseidon_perm_on_0_vec_377() {
        let poseidon = SpongePRPInstance::<Fr377>::default();
        let key = PoseidonVector::zero();
        let input = PoseidonVector::zero();
        let expected = PoseidonVector::from_elems_le_bytes(
            &OUTPUT377[0],
            &OUTPUT377[1],
            &OUTPUT377[2],
            &OUTPUT377[3],
        );
        let real_output = poseidon.prp(&key, &input);
        let round_keys = poseidon.key_schedule(&key);
        let real_output_with_round_keys = poseidon.prp_with_round_keys(&round_keys, &input);
        assert_eq!(real_output, real_output_with_round_keys);
        assert_eq!(real_output, expected);
    }

    fn test_poseidon_perm_on_0_vec_761() {
        let poseidon = SpongePRPInstance::<Fq377>::default();
        let key = PoseidonVector::zero();
        let input = PoseidonVector::zero();
        let expected = PoseidonVector::from_elems_le_bytes(
            &OUTPUT761[0],
            &OUTPUT761[1],
            &OUTPUT761[2],
            &OUTPUT761[3],
        );
        let real_output = poseidon.prp(&key, &input);
        let round_keys = poseidon.key_schedule(&key);
        let real_output_with_round_keys = poseidon.prp_with_round_keys(&round_keys, &input);
        assert_eq!(real_output, real_output_with_round_keys);
        assert_eq!(real_output, expected);
    }

    // printing vectors as hex bytes little endian
    // #[test]
    // fn print(){
    // let poseidon_hash = RescueBls4::default();
    // println!("KeySchedule:");
    // let keys = poseidon_hash.key_schedule(&RescueBls4Vector::zero());
    // for key in keys {
    // for elem in key.vec.iter() {
    // let str: Vec<String> = elem.into_repr().to_bytes_le().iter().map(|b|
    // format!("0x{:02X},", b)) .collect();
    // println!("{:?}", str.join(" "));
    // }
    // println!("],[");
    // }
    // }
}

#[cfg(test)]
mod test_permutation {
    use crate::poseidon::{
        sponge::{SpongePRPInstance, SpongePermutation, SpongePermutationT},
        traits::{MdsPseudoRandomPermute, PadSmallerChunk, VectorT},
        ParameterHelper, PoseidonVector, RATE,
    };
    use ark_bls12_377::Fq as Fq377;
    use ark_ed_on_bls12_377::Fq as Fr377;
    use ark_ed_on_bls12_381::Fq as Fr381;
    use ark_ed_on_bn254::Fq as Fr254;
    use ark_ff::PrimeField;
    use ark_std::{vec, Zero};

    #[test]
    fn test_round_keys() {
        test_round_keys_helper::<Fr254>();
        test_round_keys_helper::<Fr377>();
        test_round_keys_helper::<Fr381>();
        test_round_keys_helper::<Fq377>();
    }

    fn test_round_keys_helper<F: ParameterHelper>() {
        let poseidon_perm = SpongePRPInstance::<F>::default();
        let poseidon_hash = SpongePermutation::<F>::default();
        let zero = PoseidonVector::zero();
        let keys2 = poseidon_perm.key_schedule(&zero);
        // // the following code is used to dump the key schedule to screen
        // // in a sage friendly format
        // for e in keys2.iter() {
        //     for f in e.vec.iter() {
        //         ark_std::println!("permutation_round_key.append(0x{})",
        // f.into_repr());     }
        // }
        // assert!(false);

        assert_eq!(poseidon_hash.round_keys.to_vec(), keys2);
    }

    // hash output on vector [0, 0, 0, 0]
    // this value is cross checked with sage script
    // first three vectors of rescue761.Sponge([0,0,0,0], 4)
    const OUTPUT761: [[u8; 48]; 3] = [
        [
            0x37, 0xBE, 0x12, 0x7E, 0xDF, 0x9C, 0xBF, 0xCE, 0x78, 0xE1, 0x4F, 0xEB, 0x69, 0xAC,
            0x89, 0x53, 0xE7, 0xC4, 0x8D, 0x89, 0x90, 0x77, 0x64, 0x0D, 0xD0, 0x87, 0x42, 0xDD,
            0x1F, 0x98, 0x30, 0xC8, 0x0F, 0x12, 0x6D, 0x7A, 0x49, 0xD3, 0x22, 0x2E, 0x12, 0xBA,
            0x5B, 0x0E, 0x29, 0xB7, 0x2C, 0x01,
        ],
        [
            0x68, 0xFE, 0x2E, 0x95, 0x57, 0xDA, 0x2E, 0x36, 0xEC, 0xC1, 0xC5, 0x8A, 0x19, 0x50,
            0xD7, 0xBE, 0x11, 0x00, 0x3D, 0x5B, 0xAA, 0x8C, 0xF8, 0x45, 0x6F, 0xDC, 0xE4, 0x1F,
            0xF0, 0x35, 0xC7, 0x62, 0x6A, 0xC2, 0x33, 0xE7, 0x98, 0x9F, 0x26, 0x2A, 0x6E, 0x89,
            0xD5, 0x43, 0x21, 0xF8, 0x67, 0x01,
        ],
        [
            0x84, 0xB4, 0x93, 0x04, 0x3B, 0x23, 0x3A, 0x1B, 0x43, 0xC3, 0x61, 0x61, 0x1B, 0xA0,
            0x59, 0xFB, 0x2E, 0x88, 0x76, 0x62, 0x28, 0xBB, 0x32, 0x6F, 0x27, 0x1C, 0xA9, 0xCA,
            0x60, 0xC1, 0xE0, 0x7A, 0x7D, 0x37, 0x2F, 0x95, 0x75, 0xDD, 0x37, 0x2A, 0x70, 0xD1,
            0xE4, 0x55, 0xDB, 0x50, 0x2F, 0x00,
        ],
    ];

    // hash output on vector [0, 0, 0, 0]
    // this value is cross checked with sage script
    // first three vectors of rescue254.Sponge([0,0,0,0], 4)
    const OUTPUT254: [[u8; 32]; 3] = [
        [
            0xDD, 0xE7, 0x55, 0x8E, 0x14, 0xF9, 0x4C, 0xEE, 0x9F, 0xCC, 0xB2, 0x02, 0xFC, 0x0E,
            0x54, 0x21, 0xF2, 0xAA, 0xB8, 0x48, 0x05, 0xDB, 0x9B, 0x7A, 0xD2, 0x36, 0xA5, 0xF1,
            0x49, 0x77, 0xB4, 0x17,
        ],
        [
            0x43, 0x5F, 0x99, 0x3C, 0xB7, 0xB3, 0x84, 0x74, 0x4E, 0x80, 0x83, 0xFF, 0x73, 0x20,
            0x07, 0xD9, 0x7B, 0xEC, 0x4B, 0x90, 0x48, 0x1D, 0xFD, 0x72, 0x4C, 0xF0, 0xA5, 0x7C,
            0xDC, 0x68, 0xC0, 0x25,
        ],
        [
            0x2C, 0x7B, 0x21, 0x09, 0x9D, 0x10, 0xE9, 0x5C, 0x36, 0x3E, 0x6D, 0x20, 0x28, 0xBB,
            0xDB, 0x1E, 0xED, 0xF4, 0x22, 0x9B, 0x3A, 0xEE, 0x1E, 0x6F, 0x89, 0x13, 0x3D, 0x1E,
            0x4C, 0xA0, 0xA6, 0x23,
        ],
    ];
    // hash output on vector [0, 0, 0, 0]
    // this value is cross checked with sage script
    // first three vectors of rescue377.Sponge([0,0,0,0], 4)
    const OUTPUT377: [[u8; 32]; 3] = [
        [
            0x65, 0xF2, 0xF2, 0x74, 0x15, 0x7A, 0x5A, 0xB5, 0xE0, 0x86, 0x46, 0x9D, 0xAE, 0x27,
            0x29, 0xE0, 0x08, 0x39, 0x0D, 0xA6, 0x44, 0x5E, 0x20, 0x76, 0x23, 0x42, 0xDA, 0xF0,
            0x49, 0xA3, 0x51, 0x02,
        ],
        [
            0x67, 0xB5, 0x6A, 0xBA, 0x4B, 0xB8, 0x0F, 0xE2, 0xFC, 0x3D, 0x7E, 0xFC, 0x70, 0xCA,
            0x3D, 0x1D, 0xAC, 0xDD, 0xEA, 0x62, 0x81, 0xD7, 0x08, 0x0B, 0x38, 0x5F, 0x0A, 0x68,
            0xEC, 0xED, 0x53, 0x02,
        ],
        [
            0x10, 0xC5, 0xA0, 0xA1, 0x8E, 0x8D, 0xBC, 0xAD, 0x99, 0xC3, 0xB4, 0xE9, 0x22, 0xC9,
            0xB1, 0xCF, 0x35, 0x46, 0xE3, 0x52, 0x99, 0x5B, 0xBE, 0x6E, 0x08, 0xFF, 0x4B, 0x2F,
            0xCE, 0xF0, 0xCB, 0x0A,
        ],
    ];

    // hash output on vector [0, 0, 0, 0]
    // this value is cross checked with sage script
    // first three vectors of rescue381.Sponge([0,0,0,0], 4)
    const OUTPUT381: [[u8; 32]; 3] = [
        [
            0x12, 0x53, 0x24, 0x66, 0x84, 0xA2, 0x4D, 0x2B, 0xC7, 0x28, 0x3E, 0x0F, 0x80, 0xDF,
            0x1A, 0xC3, 0x5B, 0xA1, 0xA9, 0x5B, 0x46, 0x60, 0xBD, 0xED, 0xA6, 0xD1, 0x43, 0xB7,
            0x60, 0xCA, 0x59, 0x0D,
        ],
        [
            0x1B, 0xBE, 0xAB, 0x6C, 0xAB, 0x62, 0xB7, 0xAB, 0x19, 0xDF, 0xFF, 0x4D, 0x73, 0xB5,
            0x78, 0x30, 0x72, 0xC0, 0xC6, 0xDA, 0x1F, 0x10, 0xAD, 0xD1, 0x28, 0x65, 0xB4, 0x94,
            0x6F, 0xAC, 0xE5, 0x4B,
        ],
        [
            0x07, 0x86, 0xBD, 0x9A, 0xB3, 0x35, 0x96, 0x22, 0xF0, 0xE5, 0xEA, 0xCC, 0x9C, 0x79,
            0x89, 0x1F, 0x9D, 0x1D, 0x43, 0x44, 0xCC, 0xA9, 0x9A, 0xB0, 0x0E, 0xC0, 0x57, 0x6B,
            0x07, 0xF8, 0x53, 0x06,
        ],
    ];

    #[test]
    fn test_sponge() {
        test_sponge_helper::<Fr254>();
        test_sponge_helper::<Fr377>();
        test_sponge_helper::<Fr381>();
        test_sponge_helper::<Fq377>();
    }

    fn test_sponge_helper<F: ParameterHelper>() {
        let poseidon_prp = SpongePRPInstance::default();
        let poseidon_permutation = Permutation::from(poseidon_prp.clone());
        let mut prng = ark_std::test_rng();
        let e0 = F::rand(&mut prng);
        let e1 = F::rand(&mut prng);
        let e2 = F::rand(&mut prng);
        let e3 = F::rand(&mut prng);
        let e4 = F::rand(&mut prng);
        let e5 = F::rand(&mut prng);

        let input = [e0, e1, e2, e3, e4, e5];

        let output = poseidon_permutation
            .sponge_no_padding(&input, 1, RATE)
            .unwrap()[0];

        let zero = PoseidonVector::zero();
        let mut state = PoseidonVector {
            vec: [input[0], input[1], input[2], F::zero()],
        };
        state = poseidon_prp.prp(&zero, &state);
        state.add_assign(&PoseidonVector::pad_smaller_chunk(&input[3..6]));
        state = poseidon_prp.prp(&zero, &state);
        assert_eq!(output, state.vec[0]);
    }

    #[test]
    fn test_poseidon_hash_on_0_vec() {
        test_poseidon_hash_on_0_vec_254();
        test_poseidon_hash_on_0_vec_377();
        test_poseidon_hash_on_0_vec_381();
        test_poseidon_hash_on_0_vec_761()
    }

    pub type Permutation<F> = SpongePermutation<F>;

    fn test_poseidon_hash_on_0_vec_254() {
        let poseidon = Permutation::default();
        let input = [Fr254::zero(); 3];
        let expected = vec![
            Fr254::from_le_bytes_mod_order(&OUTPUT254[0]),
            Fr254::from_le_bytes_mod_order(&OUTPUT254[1]),
            Fr254::from_le_bytes_mod_order(&OUTPUT254[2]),
        ];
        let real_output = poseidon.sponge_no_padding(&input, 3, RATE).unwrap();
        assert_eq!(real_output, expected);
    }

    fn test_poseidon_hash_on_0_vec_377() {
        let poseidon = Permutation::default();
        let input = [Fr377::zero(); 3];
        let expected = vec![
            Fr377::from_le_bytes_mod_order(&OUTPUT377[0]),
            Fr377::from_le_bytes_mod_order(&OUTPUT377[1]),
            Fr377::from_le_bytes_mod_order(&OUTPUT377[2]),
        ];
        let real_output = poseidon.sponge_no_padding(&input, 3, RATE).unwrap();
        assert_eq!(real_output, expected);
    }

    fn test_poseidon_hash_on_0_vec_381() {
        let poseidon = Permutation::default();
        let input = [Fr381::zero(); 3];
        let expected = vec![
            Fr381::from_le_bytes_mod_order(&OUTPUT381[0]),
            Fr381::from_le_bytes_mod_order(&OUTPUT381[1]),
            Fr381::from_le_bytes_mod_order(&OUTPUT381[2]),
        ];
        let real_output = poseidon.sponge_no_padding(&input, 3, RATE).unwrap();
        assert_eq!(real_output, expected);
    }

    fn test_poseidon_hash_on_0_vec_761() {
        let poseidon = Permutation::default();
        let input = [Fq377::zero(); 3];
        let expected = vec![
            Fq377::from_le_bytes_mod_order(&OUTPUT761[0]),
            Fq377::from_le_bytes_mod_order(&OUTPUT761[1]),
            Fq377::from_le_bytes_mod_order(&OUTPUT761[2]),
        ];
        let real_output = poseidon.sponge_no_padding(&input, 3, RATE).unwrap();
        assert_eq!(real_output, expected);
    }

    #[test]
    fn test_sponge_no_padding_errors() {
        test_sponge_no_padding_errors_helper::<Fr254>();
        test_sponge_no_padding_errors_helper::<Fr377>();
        test_sponge_no_padding_errors_helper::<Fr381>();
        test_sponge_no_padding_errors_helper::<Fq377>();
    }
    fn test_sponge_no_padding_errors_helper<F: ParameterHelper>() {
        let poseidon = Permutation::default();

        let input = vec![F::from(9u64); 3];
        assert!(poseidon
            .sponge_no_padding(input.as_slice(), 1, RATE)
            .is_ok());
        let input = vec![F::from(9u64); 12];
        assert!(poseidon
            .sponge_no_padding(input.as_slice(), 1, RATE)
            .is_ok());

        // test should panic because number of inputs is not multiple of 3
        let input = vec![F::from(9u64); 10];
        assert!(poseidon
            .sponge_no_padding(input.as_slice(), 1, RATE)
            .is_err());
        let input = vec![F::from(9u64)];
        assert!(poseidon
            .sponge_no_padding(input.as_slice(), 1, RATE)
            .is_err());

        let input = vec![];
        assert!(poseidon
            .sponge_no_padding(input.as_slice(), 1, RATE)
            .is_ok());
    }

    #[test]
    fn test_fsks_no_padding_errors() {
        test_fsks_no_padding_errors_helper::<Fr254>();
        test_fsks_no_padding_errors_helper::<Fr377>();
        test_fsks_no_padding_errors_helper::<Fr381>();
        test_fsks_no_padding_errors_helper::<Fq377>();
    }
    fn test_fsks_no_padding_errors_helper<F: ParameterHelper>() {
        let poseidon = Permutation::default();
        let key = F::rand(&mut ark_std::test_rng());
        let input = vec![F::from(9u64); 4];
        assert!(poseidon
            .full_state_keyed_sponge_no_padding(&key, input.as_slice(), 1)
            .is_ok());
        let input = vec![F::from(9u64); 12];
        assert!(poseidon
            .full_state_keyed_sponge_no_padding(&key, input.as_slice(), 1)
            .is_ok());

        // test should panic because number of inputs is not multiple of 3
        let input = vec![F::from(9u64); 10];
        assert!(poseidon
            .full_state_keyed_sponge_no_padding(&key, input.as_slice(), 1)
            .is_err());
        let input = vec![F::from(9u64)];
        assert!(poseidon
            .full_state_keyed_sponge_no_padding(&key, input.as_slice(), 1)
            .is_err());

        let input = vec![];
        assert!(poseidon
            .full_state_keyed_sponge_no_padding(&key, input.as_slice(), 1)
            .is_ok());
    }

    #[test]
    fn test_variable_output_sponge_and_fsks() {
        test_variable_output_sponge_and_fsks_helper::<Fr254>();
        test_variable_output_sponge_and_fsks_helper::<Fr377>();
        test_variable_output_sponge_and_fsks_helper::<Fr381>();
        test_variable_output_sponge_and_fsks_helper::<Fq377>();
    }
    fn test_variable_output_sponge_and_fsks_helper<F: ParameterHelper>() {
        let poseidon = Permutation::default();
        let input = [F::zero(), F::one(), F::zero()];
        assert_eq!(poseidon.sponge_with_padding(&input, 0, RATE).len(), 0);
        assert_eq!(poseidon.sponge_with_padding(&input, 1, RATE).len(), 1);
        assert_eq!(poseidon.sponge_with_padding(&input, 2, RATE).len(), 2);
        assert_eq!(poseidon.sponge_with_padding(&input, 3, RATE).len(), 3);
        assert_eq!(poseidon.sponge_with_padding(&input, 10, RATE).len(), 10);

        assert_eq!(
            poseidon.sponge_no_padding(&input, 0, RATE).unwrap().len(),
            0
        );
        assert_eq!(
            poseidon.sponge_no_padding(&input, 1, RATE).unwrap().len(),
            1
        );
        assert_eq!(
            poseidon.sponge_no_padding(&input, 2, RATE).unwrap().len(),
            2
        );
        assert_eq!(
            poseidon.sponge_no_padding(&input, 3, RATE).unwrap().len(),
            3
        );
        assert_eq!(
            poseidon.sponge_no_padding(&input, 10, RATE).unwrap().len(),
            10
        );

        let key = F::rand(&mut ark_std::test_rng());
        let input = [F::zero(), F::one(), F::zero(), F::zero()];
        assert_eq!(
            poseidon
                .full_state_keyed_sponge_with_padding(&key, &input, 0)
                .len(),
            0
        );
        assert_eq!(
            poseidon
                .full_state_keyed_sponge_with_padding(&key, &input, 1)
                .len(),
            1
        );
        assert_eq!(
            poseidon
                .full_state_keyed_sponge_with_padding(&key, &input, 2)
                .len(),
            2
        );
        assert_eq!(
            poseidon
                .full_state_keyed_sponge_with_padding(&key, &input, 4)
                .len(),
            4
        );
        assert_eq!(
            poseidon
                .full_state_keyed_sponge_with_padding(&key, &input, 10)
                .len(),
            10
        );
        assert_eq!(
            poseidon
                .full_state_keyed_sponge_no_padding(&key, &input, 0)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            poseidon
                .full_state_keyed_sponge_no_padding(&key, &input, 1)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            poseidon
                .full_state_keyed_sponge_no_padding(&key, &input, 2)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            poseidon
                .full_state_keyed_sponge_no_padding(&key, &input, 4)
                .unwrap()
                .len(),
            4
        );
        assert_eq!(
            poseidon
                .full_state_keyed_sponge_no_padding(&key, &input, 10)
                .unwrap()
                .len(),
            10
        );
    }
}
