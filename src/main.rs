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

    /// encrypts message to publish in channel
    pub fn encrypt<R: RngCore>(
        &self,
        reader_ids: &Vec<usize>,
        rng: &mut R,
    ) -> ((E::G2Projective, E::G1Projective), E::Fqk) {
        let rnd_k = E::Fr::rand(rng);
        let mut p = self.channel_pubkey.p_set[self.capacity];
        let mut q = self.channel_pubkey.q;
        let mut v = self.channel_pubkey.v;

        q *= rnd_k;
        p *= rnd_k;
        v *= rnd_k;

        let mut sum_g1 = self.channel_pubkey.v.clone();
        for id in reader_ids {
            sum_g1 += &self.channel_pubkey.p_set[self.capacity + 1 - id];
        }

        sum_g1 *= rnd_k;

        let header = (q, sum_g1);
        let k = E::pairing(p, q);

        (header, k)
    }

    /// decrypts message from channel
    pub fn decrypt(
        &self,
        i: usize,
        reader_ids: &Vec<usize>,
        header: (E::G2Projective, E::G1Projective),
    ) -> E::Fqk {
        let mut k = E::pairing(header.1, self.users_pubkeys[i]);

        let mut sum_g1 = self.users_skeys[i];
        for id in reader_ids {
            sum_g1 += &self.channel_pubkey.p_set[self.capacity + 1 - id + i];
        }

        let k_denom = E::pairing(sum_g1, header.0);
        k /= &k_denom;
        k
    }
}

/// generates encryption key to encrypt the message to publish in channel
pub fn generate_key_encrypt<E: PairingEngine, R: RngCore>(
    channel_capacity: usize,
    channel_pubkey_pset: Vec<E::G1Projective>,
    channel_pubkey_q: E::G2Projective,
    channel_pubkey_v: E::G1Projective,
    reader_ids: &Vec<usize>,
    rng: &mut R,
) -> ((E::G2Projective, E::G1Projective), E::Fqk) {
    let rnd_k = E::Fr::rand(rng);
    let mut p = channel_pubkey_pset[channel_capacity].clone();
    let mut q = channel_pubkey_q.clone();
    let mut v = channel_pubkey_v.clone();

    q *= rnd_k;
    p *= rnd_k;
    v *= rnd_k;

    let mut sum_g1 = channel_pubkey_v;
    for id in reader_ids {
        sum_g1 += &channel_pubkey_pset[channel_capacity + 1 - id];
    }

    sum_g1 *= rnd_k;

    let header = (q, sum_g1);
    let k = E::pairing(p, q);

    (header, k)
}

/// generates decryption key to decrypt message in channel
pub fn generat_key_decrypt<E: PairingEngine>(
    channel_pubkey_pset: Vec<E::G1Projective>,
    channel_capacity: usize,
    user_id: usize,
    user_skey: E::G1Projective,
    users_pubkeys: Vec<E::G2Projective>,
    reader_ids: &Vec<usize>,
    header: (E::G2Projective, E::G1Projective),
) -> E::Fqk {
    let mut k = E::pairing(header.1, users_pubkeys[user_id]);

    let mut sum_g1 = user_skey;
    for i in reader_ids {
        sum_g1 += &channel_pubkey_pset[channel_capacity + 1 - i + user_id];
    }

    let k_denom = E::pairing(sum_g1, header.0);
    k /= &k_denom;
    k
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
        assert_eq!(setup.channel_pubkey.p_set.len(), capacity * 2 + 1);

        let s = &vec![0, 2]; // receiver 0 and 2 can decrypt the stream in the encryption channel
        let encrypt_setup = setup.encrypt(s, rng);

        let header = encrypt_setup.0;
        let encryption_key = encrypt_setup.1;

        // generate keys for all users (only s0 and s1 should have valid key)
        let key_s0 = setup.decrypt(0, s, header);
        let key_s1 = setup.decrypt(0, s, header);
        let key_s2 = setup.decrypt(0, s, header);

        assert_eq!(key_s0, encryption_key);
        assert_eq!(key_s2, encryption_key);
        assert_ne!(key_s1, encryption_key)
    }
}
