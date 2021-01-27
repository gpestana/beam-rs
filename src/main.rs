#![allow(unused_imports)] // remove after dev
#![allow(dead_code)] // remove after dev

// TODO: refactor to use abstract pairing engine
use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::{Field, UniformRand, Zero};
use rand::{thread_rng, CryptoRng, Rng};

// ark_bls12_381
use ark_bls12_381::{Fr, G1Projective as G1, G2Projective as G2, Bls12_381};
use ark_ff::One;

pub struct BroadcastChannel<E: PairingEngine> {
    pub pubkeys: (Vec<E::G1Projective>, E::G1Projective)
}

pub struct Setup {
    pub pubkey: (Vec<G1>, G1),
    pub skeys: Vec<G1>,
}

pub fn new_setup(n: usize) -> Setup {
    let rng = &mut thread_rng();
    let rnd_a = Fr::rand(rng);
    let rnd_y = Fr::rand(rng);

    let mut pk_x = vec![G1::prime_subgroup_generator(); 2 * n + 1];
    let mut sks = vec![G1::prime_subgroup_generator(); 2 * n];

    let mut v = G1::prime_subgroup_generator();
    v *= rnd_y;

    let mut i = Fr::zero();

    for idx in 1..pk_x.len() {
        i += Fr::one();
        let mut mut_i = i.clone();

        mut_i *= rnd_a;
        pk_x[idx] *= mut_i;

        sks[idx-1] *= rnd_y;
    }

    Setup {
        pubkey: (pk_x, v),
        skeys: sks,
    }
}

pub fn encrypt(pkey: (Vec<G1>, G1), n: usize) {
    let rng = &mut thread_rng();
    let rnd_t = Fr::rand(rng);

    let b: G2 = rng.gen();
    //let k = Bls12_381::pairing(pkey.0[n], pkey.0[0]);
    let k = Bls12_381::pairing(pkey.0[n], b);
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_e2e() {
        let n = 3; // number of receivers
        let setup = new_setup(n);

        assert_eq!(setup.pubkey.0.len(), n * 2 + 1);
        assert_eq!(setup.skeys.len(), n * 2);
    }
}
