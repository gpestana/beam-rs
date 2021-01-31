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
<<<<<<< HEAD

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
    use super::*;
    use ark_bls12_381::{Bls12_381, G1Projective, G2Projective};

    #[test]
    fn test_pen_and_paper() {
        use rand::Rng;
        use ark_bls12_381::Fr;
        use std::collections::HashMap;
        use std::ops::DivAssign;

        let mut rng = &mut thread_rng(); 

        let mut reader_set = HashMap::new();
        let channel_capacity = 3;
        reader_set.insert("user_1", 1);
        reader_set.insert("user_2", 2);
        reader_set.insert("user_3", 3);

        // 1. SETUP
        let mut alpha: Fr = UniformRand::rand(&mut rng);
        let mut gamma: Fr = UniformRand::rand(&mut rng);

        // SETUP::p_set
        let mut p_set: Vec::<G1Projective> = vec![rng.gen(); 2 * channel_capacity];

        let P: G1Projective = rng.gen();
        let mut V: G1Projective = P.clone();
        V *= gamma;

        let mut p1 = P.clone();
        p1 *= alpha;

        let mut p2 = P.clone();
        p2 *= alpha;
        p2 *= alpha;

        let mut p3 = P.clone();
        p3 *= alpha;
        p3 *= alpha;
        p3 *= alpha;

        let mut p5 = P.clone();
        p5 *= alpha;
        p5 *= alpha;
        p5 *= alpha;
        p5 *= alpha;
        p5 *= alpha;

        let mut p6 = P.clone();
        p6 *= alpha;
        p6 *= alpha;
        p6 *= alpha;
        p6 *= alpha;
        p6 *= alpha;
        p6 *= alpha;

        p_set[0] = P;
        p_set[1] = p1;
        p_set[2] = p2;
        p_set[3] = p3;
        p_set[4] = p5;
        p_set[5] = p6;
        
        // SETUP::q_set
        let mut q_set: Vec::<G2Projective> = vec![rng.gen(); channel_capacity]; 
        
        let Q: G2Projective = rng.gen();

        let mut q1 = Q.clone();
        q1 *= alpha;

        let mut q2 = Q.clone();
        q2 *= alpha;
        q2 *= alpha;

        let mut q3 = Q.clone();
        q3 *= alpha;
        q3 *= alpha;
        q3 *= alpha;

        q_set[0] = q1;
        q_set[1] = q2;
        q_set[2] = q3;

        // SETUP::users_skeys
        let mut users_skeys: Vec::<G1Projective> = vec![rng.gen(); channel_capacity];

        let mut d1 = P.clone();
        d1 *= gamma;

        let mut d2 = P.clone();
        d2 *= gamma;
        d2 *= gamma;

        let mut d3 = P.clone();
        d3 *= gamma;
        d3 *= gamma;
        d3 *= gamma;

        users_skeys[0] = d1;
        users_skeys[1] = d2;
        users_skeys[2] = d3;


        // 2. ENCRYPT
        // s = {1, 3}, r = {2}
        let mut k: Fr = UniformRand::rand(&mut rng);

        let mut Q_k = q_set[1];
        Q_k *= k;

        let mut K = Bls12_381::pairing(p_set[channel_capacity], Q_k); 

        let mut header0 = Q;
        header0 *= k;


        // s = {1, 3}
        let mut j = 1; // user 1
        let mut header1 = p_set[channel_capacity + 1 - j];
        let mut j = 3; // user_3
        header1 += p_set[channel_capacity + 1 - j];

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

        assert_eq!(K1, K3);
    }
=======
}

/// generates encryption key to encrypt the message to publish in channel
pub fn generate_key_encrypt<E: PairingEngine, R: RngCore>(
    channel_capacity: usize,
    channel_pubkey_pset: &Vec<E::G1Projective>,
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
pub fn generate_key_decrypt<E: PairingEngine>(
    channel_pubkey_pset: &Vec<E::G1Projective>,
    channel_capacity: usize,
    user_id: usize,
    user_skey: E::G1Projective,
    users_pubkeys: &Vec<E::G2Projective>,
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
    use ark_bls12_381::{Bls12_381, Fq};
>>>>>>> 299184a... Refactor

    #[test]
    fn test_e2e() {
        let rng = &mut thread_rng();
        let capacity = 3; // number of receivers

        let setup = BroadcastChannel::<Bls12_381>::new(capacity, rng);

        assert_eq!(setup.users_skeys.len(), capacity);
        assert_eq!(setup.users_pubkeys.len(), capacity);
        assert_eq!(setup.channel_pubkey.p_set.len(), capacity * 2);

<<<<<<< HEAD
        let s = vec![1, 3]; // receiver 0 and 2 can decrypt the stream in the encryption channel
        let encrypt_setup = setup.encrypt(s.clone(), rng);
=======
        let s = &vec![0, 2]; // receiver 0 and 2 can decrypt the stream in the encryption channel
        let encrypt_setup = generate_key_encrypt(
            capacity,
            &setup.channel_pubkey.p_set,
            setup.channel_pubkey.q,
            setup.channel_pubkey.v,
            s,
            rng,
        );
>>>>>>> 299184a... Refactor

        let header = encrypt_setup.0;
        let encryption_key = encrypt_setup.1;

<<<<<<< HEAD
        // generates keys for all users (only s1 and s2 should have valid key)
        let key_s1 = setup.decrypt(1, s.clone(), header);
        //let key_s2 = setup.decrypt(1, s.clone(), header);
        let key_s3 = setup.decrypt(3, s.clone(), header);

        //assert_eq!(key_s1, key_s3);
        //assert_eq!(key_s1, encryption_key);
        //assert_eq!(key_s3, encryption_key);
        //assert_ne!(key_s2, encryption_key)
=======
        // generate keys for all users (only s0 and s1 should have valid key)
        let key_s0: Fq = generate_key_decrypt(
            &setup.channel_pubkey.p_set,
            capacity,
            0,
            setup.users_skeys,
            &setup.users_pubkeys,
            s,
            header,
        );
        //let key_s1 = setup.decrypt(0, s, header);
        //let key_s2 = setup.decrypt(0, s, header);

        //assert_eq!(key_s0, encryption_key);
        //assert_eq!(key_s2, encryption_key);
        //assert_ne!(key_s1, encryption_key)
>>>>>>> 299184a... Refactor
    }
}
