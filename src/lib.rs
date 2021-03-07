#![allow(non_snake_case, dead_code, unused_mut)] // TODO: remove after dev

use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::{One, UniformRand, Zero};
use rand::RngCore;

/// Key pair
#[derive(Clone, Copy)]
pub struct KeyPair<E: PairingEngine> {
    /// Public Key
    public_key: E::G2Projective,
    /// Private Key
    private_key: E::G1Projective,
}

/// Participant on the broadcast channel (consumer)
pub struct Participant<E: PairingEngine> {
    id: usize,
    key_pair: KeyPair<E>,
}

pub struct BroadcastPubKey<E: PairingEngine> {
    pub p_set: Vec<E::G1Projective>,
    pub v: E::G1Projective,

    pub q: E::G2Projective,
    pub q_1: E::G2Projective,
}

pub struct BroadcastChannel<E: PairingEngine> {
    pub channel_pubkey: BroadcastPubKey<E>,
    pub participants: Vec<Participant<E>>,
    pub capacity: usize,
}

impl<E: PairingEngine> BroadcastChannel<E> {

    /// setup for a new broadcast channel with `n` readers
    pub fn new<R: RngCore>(capacity: usize, rng: &mut R) -> Self {
        let p_gen = E::G1Projective::prime_subgroup_generator();
        let q_gen = E::G2Projective::prime_subgroup_generator();
        let rnd_alpha = E::Fr::rand(rng);
        let rnd_gamma = E::Fr::rand(rng);

        let mut p_set = Vec::new();

        let mut v = E::G1Projective::prime_subgroup_generator();
        v *= rnd_gamma;

        p_set.push(p_gen);
        for i in 1..2 * capacity + 1 {
            if i == capacity + 1 {
                continue
            }
            p_set.push(exp(&p_gen, rnd_alpha, i));
        }

        let mut participants: Vec::<Participant<E>> = Vec::new();
        for i in 0..capacity {
            let public_key = exp(&q_gen, E::Fr::one(), i);
            let private_key = exp(&p_set[i], rnd_gamma, i);
            let key_pair = KeyPair{public_key, private_key};
            participants.push(Participant{
                id: i + 1,
                key_pair,
            });
        }

        let channel_pubkey = BroadcastPubKey {
            p_set,
            v,
            q: q_gen,
            q_1: exp(&q_gen, E::Fr::one(), 1),
        };

        BroadcastChannel {
            capacity,
            channel_pubkey,
            participants,
        }
    }

    /// encrypts message to publish in channel
    pub fn encrypt<R: RngCore>(
        &self,
        reader_ids: Vec<usize>,
        rng: &mut R,
    ) -> ((E::G2Projective, E::G1Projective), E::Fqk) {
        let rnd_k = E::Fr::rand(rng);

        // K
        let mut pn = self.channel_pubkey.p_set[self.capacity];
        pn *= rnd_k;
        let k = E::pairing(pn, self.channel_pubkey.q_1);

        // Header
        let mut sum_g1 = self.channel_pubkey.v; // init Sum as `Sum=V`

        for j in reader_ids {
            sum_g1 += &self.channel_pubkey.p_set[self.capacity + 1 - j];
        }

        sum_g1 *= rnd_k;

        // kQ
        let mut q = self.channel_pubkey.q;
        q *= rnd_k;

        let header = (q, sum_g1);

        (header, k)
    }

    /// decrypts message from channel
    pub fn decrypt(
        &self,
        i: usize,
        reader_ids: Vec<usize>,
        header: (E::G2Projective, E::G1Projective),
    ) -> E::Fqk {
        let user_keypair = self.participants[i - 1].key_pair;
        let mut k = E::pairing(header.1, user_keypair.public_key);

        let mut sum_g1 = user_keypair.private_key;
        for j in reader_ids {
            if j == i {
                continue;
            }
            sum_g1 += &self.channel_pubkey.p_set[self.capacity - j + i];
            //sum_g1 += &self.channel_pubkey.p_set[self.capacity + 1 - j + i]; // TODO
        }

        let k_denom = E::pairing(sum_g1, header.0);
        k /= &k_denom;
        k
    }
}

/// Calculates exponetiation of g with f, i times
fn exp<P>(g: &P, f: P::ScalarField, i: usize) -> P
where
    P: ProjectiveCurve,
{
    let mut g_result = *g;
    for _ in 0..i {
        g_result *= f
    }
    g_result
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use rand::thread_rng;

    #[test]
    fn test_e2e() {
        let rng = &mut thread_rng();
        let capacity = 3; // number of receivers

        let setup = BroadcastChannel::<Bls12_381>::new(capacity, rng);

        assert_eq!(setup.participants.len(), capacity);
        assert_eq!(setup.channel_pubkey.p_set.len(), capacity * 2);

        let s = vec![1, 2, 3]; // receiver 0 and 2 can decrypt the stream in the encryption channel
        let encrypt_setup = setup.encrypt(s.clone(), rng);

        // ( HEADER: (E::G2Projective, E::G1Projective), KEY: E::Fqk)
        let header = encrypt_setup.0;
        let encryption_key = encrypt_setup.1;

        // generates keys for all users (only s1 and s2 should have valid key)
        let key_s1 = setup.decrypt(1, s.clone(), header);
        let key_s2 = setup.decrypt(2, s.clone(), header);
        let key_s3 = setup.decrypt(3, s.clone(), header);

        //assert_eq!(key_s1, key_s3);
        assert_eq!(key_s1, encryption_key);
        assert_eq!(key_s2, encryption_key);
        assert_eq!(key_s3, encryption_key);
    }
}
