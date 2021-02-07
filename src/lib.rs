use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::{One, UniformRand, Zero};
use rand::RngCore;

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
        let mut k = E::pairing(header.1, self.users_pubkeys[i - 1]);

        let mut sum_g1 = self.users_skeys[i - 1];
        for j in reader_ids {
            if j == i {
                continue;
            }
            let idx = self.capacity + 1 - j + i;
            sum_g1 += &self.channel_pubkey.p_set[idx - 1];
        }

        let k_denom = E::pairing(sum_g1, header.0);
        k /= &k_denom;
        k
    }
}

#[cfg(test)]
mod test {
    use std::println;

    use super::*;
    use ark_bls12_381::{Bls12_381, G1Projective, G2Projective};
    use rand::thread_rng;

    #[test]
    fn test_pen_and_paper() {
        use ark_bls12_381::Fr;
        use rand::Rng;
        use std::collections::HashMap;
        use std::ops::DivAssign;

        let mut rng = &mut thread_rng();

        // 1. SETUP
        let channel_capacity = 3;
        let alpha: Fr = UniformRand::rand(&mut rng);
        let gamma: Fr = UniformRand::rand(&mut rng);

        // SETUP::p_set
        let P: G1Projective = rng.gen();

        let mut V: G1Projective = P.clone();
        V *= gamma;

        let mut p_set: Vec<G1Projective> = vec![P; 2 * channel_capacity];

        // P_1
        p_set[1] *= alpha;

        // P_2
        p_set[2] *= alpha;
        p_set[2] *= alpha;

        // P_3
        p_set[3] *= alpha;
        p_set[3] *= alpha;
        p_set[3] *= alpha;

        // P_5
        p_set[4] *= alpha;
        p_set[4] *= alpha;
        p_set[4] *= alpha;
        p_set[4] *= alpha;
        p_set[4] *= alpha;

        // P_6
        p_set[5] *= alpha;
        p_set[5] *= alpha;
        p_set[5] *= alpha;
        p_set[5] *= alpha;
        p_set[5] *= alpha;
        p_set[5] *= alpha;

        // SETUP::q_set
        let Q: G2Projective = rng.gen();
        let mut q_set: Vec<G2Projective> = vec![Q; channel_capacity];

        // Q_1
        q_set[0] *= alpha;

        // Q_2
        q_set[1] *= alpha;
        q_set[1] *= alpha;

        // Q_3
        q_set[2] *= alpha;
        q_set[2] *= alpha;
        q_set[2] *= alpha;

        // SETUP::users_skeys
        let mut users_skeys: Vec<G1Projective> = vec![P; channel_capacity];

        // D_1
        users_skeys[0] *= gamma;

        // D_2
        users_skeys[1] *= gamma;
        users_skeys[1] *= gamma;

        // D_3
        users_skeys[2] *= gamma;
        users_skeys[2] *= gamma;
        users_skeys[2] *= gamma;

        // 2. ENCRYPT
        // s = {1, 3}, r = {2}
        let mut k: Fr = UniformRand::rand(&mut rng);

        let mut q_1k = q_set[0];
        q_1k *= k;

        let mut K = Bls12_381::pairing(p_set[channel_capacity], q_1k);

        let mut header0 = Q;
        header0 *= k;

        // s = {1, 3}
        let mut j = 1; // user 1
        let mut header1 = p_set[channel_capacity + 1 - j];

        let mut j = 3; // user_3
        header1 += p_set[channel_capacity + 1 - j];
    
        // header1 = k*v + k*Sum
        let mut v = V.clone();
        v *= k;
        header1 *= k;

        header1 += v;

        let header = (header0, header1);

        // 3. DECRYPT
        // s = {1, 3}, r = {2}

        // s1 key:
        let mut j = 1; // user 1

        let mut K1 = Bls12_381::pairing(header1, q_set[j - 1]);
        let mut sum_1 = p_set[channel_capacity + 1 - j];
        sum_1 += users_skeys[0];
        let k1_denom = Bls12_381::pairing(sum_1, header0);
        K1.div_assign(k1_denom);

        // s3 key:
        let mut j = 3; // user 3

        let mut K3 = Bls12_381::pairing(header1, q_set[j - 1]);
        let mut sum_1 = p_set[channel_capacity + 1 - j];
        sum_1 += users_skeys[2];
        let k3_denom = Bls12_381::pairing(sum_1, header0);
        K3.div_assign(k3_denom);

        assert_eq!(K1, K);
        assert_eq!(K1, K3);
    }


    #[test]
    fn test_e2e() {
        let rng = &mut thread_rng();
        let capacity = 3; // number of receivers

        let setup = BroadcastChannel::<Bls12_381>::new(capacity, rng);

        assert_eq!(setup.users_skeys.len(), capacity);
        assert_eq!(setup.users_pubkeys.len(), capacity);
        assert_eq!(setup.channel_pubkey.p_set.len(), capacity * 2);

        let s = vec![1, 3]; // receiver 0 and 2 can decrypt the stream in the encryption channel
        let encrypt_setup = setup.encrypt(s.clone(), rng);

        use ark_ff::ToBytes;

        // ( HEADER: (E::G2Projective, E::G1Projective), KEY: E::Fqk)
        let header = encrypt_setup.0;
        let encryption_key = encrypt_setup.1;

        // generates keys for all users (only s1 and s2 should have valid key)
        let key_s1 = setup.decrypt(1, s.clone(), header);
        //let key_s2 = setup.decrypt(1, s.clone(), header);
        let key_s3 = setup.decrypt(3, s.clone(), header);

        //assert_eq!(key_s1, key_s3);
        //assert_eq!(key_s1, encryption_key);
        //assert_eq!(key_s3, encryption_key);
        //assert_ne!(key_s2, encryption_key)
    }
}
