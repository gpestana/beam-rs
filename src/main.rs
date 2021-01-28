use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::{One, UniformRand, Zero};
use rand::{thread_rng, RngCore};

pub struct BroadcastPubKey<E: PairingEngine> {
    pub p_set: Vec<E::G1Projective>,
    pub v: E::G1Projective,
    pub q: E::G2Projective,
    pub q_1: E::G2Projective,
}

pub struct BroadcastChannel<E: PairingEngine> {
    pub channel_pubkey: BroadcastPubKey<E>,
    pub users_pubkeys: Vec<E::G2Projective>,
    pub users_skeys: Vec<E::G1Projective>,
    pub capacity: usize,
}

impl<E: PairingEngine> BroadcastChannel<E> {
    /// setup for a new broadcast channel with `n` readers
    pub fn new<R: RngCore>(capacity: usize, rng: &mut R) -> Self {
        let rnd_alpha = E::Fr::rand(rng);
        let rnd_gamma = E::Fr::rand(rng);

        let mut p_set = vec![E::G1Projective::prime_subgroup_generator(); 2 * capacity + 1];
        let mut users_pubkeys = vec![E::G2Projective::prime_subgroup_generator(); capacity];
        let mut users_skeys = vec![E::G1Projective::prime_subgroup_generator(); capacity];

        let mut v = E::G1Projective::prime_subgroup_generator();
        v *= rnd_gamma;

        let mut i = E::Fr::zero();

        for idx in 1..p_set.len() {
            i += &E::Fr::one();

            if idx == capacity + 1 {
                continue;
            }

            let mut mut_i = i.clone();
            mut_i *= &rnd_alpha;

            p_set[idx] *= mut_i;

            if idx <= capacity - 1 {
                users_pubkeys[idx] *= mut_i;

                let mut ski = p_set[idx];
                ski *= rnd_gamma;
                users_skeys[idx] = ski;
            }
        }

        let channel_pubkey = BroadcastPubKey {
            p_set: p_set,
            v: v,
            q: users_pubkeys[0],
            q_1: users_pubkeys[1],
        };

        BroadcastChannel {
            channel_pubkey,
            users_pubkeys,
            users_skeys,
            capacity,
        }
    }

    /// encrypts message to publish in channe
    pub fn encrypt<R: RngCore>(&self, reader_ids: Vec<usize>, rng: &mut R) -> E::Fqk {
        let rnd_k = E::Fr::rand(rng);
        let mut p = self.channel_pubkey.p_set[self.capacity];
        let q = self.channel_pubkey.q;
        p *= rnd_k; // correct?

        E::pairing(p, q)
    }

    /// decrypts message from channel
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

        assert_eq!(setup.users_skeys.len(), capacity);
        assert_eq!(setup.users_pubkeys.len(), capacity);
        assert_eq!(setup.channel_pubkey.p_set.len(), capacity * 2 + 1);
    }
}
