use std::collections::HashMap;

use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::UniformRand;
use rand::RngCore;

/// Key pair
#[derive(Clone, Copy, Debug)]
pub struct KeyPair<E: PairingEngine> {
    /// Public Key
    public_key: E::G2Projective,
    /// Private Key
    private_key: E::G1Projective,
}

impl<E: PairingEngine> KeyPair<E> {
    /// derives key to decryp to message published in the broadcast channel
    pub fn derive_key(
        &self,
        id: usize,
        reader_ids: Vec<usize>,
        channel_capacity: usize,
        channel_p_set: Vec<E::G1Projective>,
        header: (E::G2Projective, E::G1Projective),
    ) -> E::Fqk {
        let mut k = E::pairing(header.1, self.public_key);

        let mut sum_g1 = self.private_key;
        for j in reader_ids {
            if j == id {
                continue;
            }
            sum_g1 += &channel_p_set[channel_capacity + 1 - j + id];
        }

        let k_denom = E::pairing(sum_g1, header.0);
        k /= &k_denom;
        k
    }
}

/// ReaderPool of channel consumers of the channel
#[derive(Clone, Debug)]
pub struct ReaderPool<E: PairingEngine> {
    pub list: HashMap<usize, KeyPair<E>>, // perhaps change from usize to an hash(usize)?
}

impl<E: PairingEngine> ReaderPool<E> {
    pub fn new() -> Self {
        return ReaderPool {
            list: HashMap::new(),
        };
    }
}

pub struct BroadcastPubKey<E: PairingEngine> {
    pub p_set: Vec<E::G1Projective>,
    pub v: E::G1Projective,
    pub q: E::G2Projective,
    pub q_1: E::G2Projective,
}

pub struct BroadcastChannel<E: PairingEngine> {
    pub channel_pubkey: BroadcastPubKey<E>,
    pub participants: ReaderPool<E>,
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

        let mut participants = ReaderPool::new();

        let mut v = E::G1Projective::prime_subgroup_generator();
        v *= rnd_gamma;

        p_set.push(p_gen);
        for i in 1..2 * capacity + 1 {
            if i == capacity + 1 {
                continue;
            }

            // TODO: keep state of the previous run to cut on computation
            p_set.push(exp(&p_gen, rnd_alpha, i));
        }

        for i in 0..capacity {
            let public_key = exp(&q_gen, rnd_alpha, i);
            let private_key = exp(&p_set[i], rnd_gamma, i);

            let key_pair = KeyPair {
                public_key,
                private_key,
            };

            participants.list.insert(i, key_pair);
        }

        let channel_pubkey = BroadcastPubKey {
            p_set,
            v,
            q: q_gen,
            q_1: exp(&q_gen, rnd_alpha, 1),
        };

        BroadcastChannel {
            capacity,
            channel_pubkey,
            participants,
        }
    }

    /// encrypts message to publish in the channel
    pub fn encrypt<R: RngCore>(
        &self,
        reader_ids: Vec<usize>,
        rng: &mut R,
    ) -> ((E::G2Projective, E::G1Projective), E::Fqk) {
        let rnd_k = E::Fr::rand(rng);

        // K
        // K=e(Pn+1,Q)^k
        let mut qk = self.channel_pubkey.q_1;
        qk *= rnd_k;
        let k = E::pairing(self.channel_pubkey.p_set[self.capacity], qk);

        // Header
        let mut sum_g1 = self.channel_pubkey.v; // init Sum as `Sum = V`

        for j in reader_ids {
            sum_g1 += &self.channel_pubkey.p_set[self.capacity + 1 - j];
        }

        sum_g1 *= rnd_k;

        let header = (qk, sum_g1);

        (header, k)
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

        assert_eq!(setup.participants.list.len(), capacity);
        assert_eq!(setup.channel_pubkey.p_set.len(), capacity * 2);

        let s = vec![0, 1, 2]; // receiver group
        let encrypt_setup = setup.encrypt(s.clone(), rng);

        let header = encrypt_setup.0;
        let encryption_key = encrypt_setup.1;

        let reader0 = setup.participants.list[&0];
        let key_r0 = reader0.derive_key(0, s, capacity, setup.channel_pubkey.p_set, header);
        assert_eq!(key_r0, encryption_key);

        //let key_s2 = setup.decrypt(1, s.clone(), header);
        //assert_eq!(key_s2, encryption_key);

        //let key_s3 = setup.decrypt(2, s.clone(), header);
        //assert_eq!(key_s3, encryption_key);
    }
}
