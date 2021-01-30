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

        let mut p_set = vec![E::G1Projective::prime_subgroup_generator(); 2 * capacity];

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

            if idx <= capacity {
                users_pubkeys[idx - 1] *= mut_i;

                let mut ski = p_set[idx];
                ski *= rnd_gamma;
                users_skeys[idx - 1] = ski;
            }
        }

        let channel_pubkey = BroadcastPubKey {
            p_set: p_set,
            v: v,
            q: E::G2Projective::prime_subgroup_generator(),
            q_1: users_pubkeys[0],
        };

        BroadcastChannel {
            channel_pubkey,
            users_pubkeys,
            users_skeys,
            capacity,
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
            let idx = self.capacity + 1 - j;
            sum_g1 += &self.channel_pubkey.p_set[idx];
        }

        // k(V + Sum)
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
        let mut k = E::pairing(header.1, self.users_pubkeys[i]);

        let mut sum_g1 = self.users_skeys[i];
        for j in reader_ids {
            if j == i {
                // skip if j == i
                continue;
            }
            let idx = self.capacity + 1 - j + i;
            sum_g1 += &self.channel_pubkey.p_set[idx];
        }

        let k_denom = E::pairing(sum_g1, header.0);
        k /= &k_denom;
        k
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::Bls12_381;

    #[test]
    fn test_e2e() {
        let rng = &mut thread_rng();
        let capacity = 3; // number of receivers

        let setup = BroadcastChannel::<Bls12_381>::new(capacity, rng);

        assert_eq!(setup.users_skeys.len(), capacity);
        assert_eq!(setup.users_pubkeys.len(), capacity);
        assert_eq!(setup.channel_pubkey.p_set.len(), capacity * 2);

        let s = vec![0, 2]; // receiver 0 and 2 can decrypt the stream in the encryption channel
        let encrypt_setup = setup.encrypt(s.clone(), rng);

        let header = encrypt_setup.0;
        let encryption_key = encrypt_setup.1;

        // generates keys for all users (only s0 and s1 should have valid key)
        let key_s0 = setup.decrypt(0, s.clone(), header);
        //let key_s1 = setup.decrypt(1, s.clone(), header);
        let key_s2 = setup.decrypt(2, s.clone(), header);

        assert_eq!(key_s0, key_s2);

        assert_eq!(key_s0, encryption_key);
        assert_eq!(key_s2, encryption_key);
        //assert_ne!(key_s1, encryption_key)
    }
}
