#![allow(unused_imports)] // remove after dev
#![allow(dead_code)] // remove after dev

use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::{Field, UniformRand, Zero, One};
use rand::{thread_rng, CryptoRng, Rng, RngCore};

pub struct BroadcastChannel<E: PairingEngine> {
    pub pubkeys: (Vec<E::G1Projective>, E::G1Projective)
}

impl<E: PairingEngine> BroadcastChannel<E> {
    pub fn new<R: RngCore>(
        capacity: usize,
        rng: &mut R,
    ) -> (Self, Vec<E::G1Projective>) {

    let rnd_a = E::Fr::rand(rng);
    let rnd_y = E::Fr::rand(rng);

    let mut pk_x = vec![E::G1Projective::prime_subgroup_generator(); 2 * capacity + 1];
    let mut sks = vec![E::G1Projective::prime_subgroup_generator(); 2 * capacity];

    let mut v = E::G1Projective::prime_subgroup_generator();
    v *= rnd_y;

    let mut i = E::Fr::zero();

    for idx in 1..pk_x.len() {
        i += &E::Fr::one();
        let mut mut_i = i.clone();

        mut_i *= &rnd_a;
        pk_x[idx] *= mut_i;

        sks[idx-1] *= rnd_y;
    }

    (BroadcastChannel{pubkeys: (pk_x, v)}, sks)
    }

    pub fn encrypt(&self) {}
    pub fn decrypt(&self) {}
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::Bls12_381;

    #[test]
    fn test_e2e() {
        let rnd = &mut thread_rng(); 
        let capacity = 3; // number of receivers

        let setup = BroadcastChannel::<Bls12_381>::new(capacity, rnd);

        assert_eq!(setup.0.pubkeys.0.len(), capacity * 2 + 1);
        assert_eq!(setup.1.len(), capacity * 2);
    }
}
