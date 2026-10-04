//! BoringSSL-compatible SPAKE2, the **curve25519** variant used by ADB
//! wireless pairing (`packages/modules/adb/.../spake25519.cc`).
//!
//! This is *not* the RustCrypto `spake2` crate (Ed25519, RFC-draft variant).
//! ADB uses BoringSSL's construction:
//! - compressed Ed25519 points, 32-byte messages;
//! - SHA-512 identity and password hashes;
//! - ephemeral scalar `8·sc_reduce(rand)` (cofactor-cleared);
//! - password scalar `s = x25519_sc_reduce(SHA512(pw))` over the **full
//!   64-byte** hash (mod l), then `ps = s + (s&7)·l` (multiple of 8,
//!   < 8·l) — the "cofactor hack";
//! - fixed blinding points M (client) / N (server);
//! - key = SHA512 over a length-prefixed transcript.
//!
//! Because the raw password scalar exceeds l, mask points are computed with
//! explicit `ps·M = (ps mod l)·M + (ps div l)·(l·M)` in the full group,
//! exactly as BoringSSL's x25519 ladder does.

use std::convert::TryInto;

use anyhow::{anyhow, Context, Result};
use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::clamp_integer,
    Scalar,
};
use rand::RngCore;
use sha2::{Digest, Sha512};

/// Identity of the pairing client (host side), per AOSP `spake25519.cc`.
pub const CLIENT_ID: &str = "adb pair client";
/// Identity of the pairing server (device side).
pub const SERVER_ID: &str = "adb pair server";

/// BoringSSL fixed blinding point M (client / alice).
pub const M_POINT: [u8; 32] = [
    0x5a, 0xda, 0x7e, 0x4b, 0xf6, 0xdd, 0xd9, 0xad, 0xb6, 0x62, 0x6d, 0x32, 0x13, 0x1c,
    0x6b, 0x5c, 0x51, 0xa1, 0xe3, 0x47, 0xa3, 0x47, 0x8f, 0x53, 0xcf, 0xcf, 0x44, 0x1b,
    0x88, 0xee, 0xd1, 0x2e,
];
/// BoringSSL fixed blinding point N (server / bob).
pub const N_POINT: [u8; 32] = [
    0x10, 0xe3, 0xdf, 0x0a, 0xe3, 0x7d, 0x8e, 0x7a, 0x99, 0xb5, 0xfe, 0x74, 0xb4, 0x46,
    0x72, 0x10, 0x3d, 0xbd, 0xdc, 0xbd, 0x06, 0xaf, 0x68, 0x0d, 0x71, 0x32, 0x9a, 0x11,
    0x69, 0x3b, 0xc7, 0x78,
];

/// Prime order of the ed25519 basepoint subgroup (BoringSSL `kOrder`),
/// little-endian 64-bit limbs of l = 2^252 + 27742317777372353535851937790883648493.
const L: [u64; 4] = [
    0x5812_631A_5CF5_D3ED,
    0x14DE_F9DE_A2F7_9CD6,
    0,
    1 << 60,
];

fn point_from_bytes(b: [u8; 32]) -> Result<EdwardsPoint> {
    CompressedEdwardsY(b)
        .decompress()
        .context("decompress ed25519 point")
}

fn lenp(v: &[u8]) -> Vec<u8> {
    let mut out = (v.len() as u64).to_le_bytes().to_vec();
    out.extend_from_slice(v);
    out
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// `adb pair` side: identity "adb pair client".
    Client,
    /// Device side: identity "adb pair server".
    Server,
}

impl Role {
    fn my_point(&self) -> EdwardsPoint {
        match self {
            Role::Client => point_from_bytes(M_POINT).expect("M_POINT is valid"),
            Role::Server => point_from_bytes(N_POINT).expect("N_POINT is valid"),
        }
    }

    fn their_point(&self) -> EdwardsPoint {
        match self {
            Role::Client => point_from_bytes(N_POINT).expect("N_POINT is valid"),
            Role::Server => point_from_bytes(M_POINT).expect("M_POINT is valid"),
        }
    }
}

pub struct Spake2 {
    my_id: Vec<u8>,
    their_id: Vec<u8>,
    role: Role,
    /// 8·clamp(rand) reduced mod l (basepoint products are unaffected).
    private: Scalar,
    /// Full SHA-512 of the password (64 bytes).
    password_hash: [u8; 64],
    /// Raw (unreduced) clamped password scalar, 32 bytes LE.
    password_raw: [u8; 32],
    /// My blinded ephemeral point, compressed (32 bytes).
    my_msg: [u8; 32],
    their_msg: Option<[u8; 32]>,
    dh: Option<[u8; 32]>,
    key: Option<[u8; 64]>,
}

impl Spake2 {
    /// New client (host) context. `password` is the SPAKE2 password:
    /// pairing-code bytes followed by the 64 exported keying-material bytes.
    pub fn new_client(password: &[u8]) -> Self {
        Self::new(CLIENT_ID, SERVER_ID, Role::Client, password)
    }

    /// New server (device) context.
    pub fn new_server(password: &[u8]) -> Self {
        Self::new(SERVER_ID, CLIENT_ID, Role::Server, password)
    }

    fn new(my_id: &str, their_id: &str, role: Role, password: &[u8]) -> Self {
        let mut eph = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut eph);
        let c = clamp_integer(eph);
        // BoringSSL: private = 8*clamp(rand), used raw; for products with the
        // basepoint (order l) the reduction mod l is equivalent.
        let private = Scalar::from_bytes_mod_order(c) * Scalar::from(8u64);
        Self::with_private(my_id, their_id, role, password, private)
    }

    fn with_private(
        my_id: &str,
        their_id: &str,
        role: Role,
        password: &[u8],
        private: Scalar,
    ) -> Self {
        let password_hash: [u8; 64] = Sha512::digest(password)
            .as_slice()
            .try_into()
            .expect("sha512 is 64 bytes");
        let password_raw = password_scalar(&password_hash);

        let p = EdwardsPoint::mul_base(&private);

        let mask = raw_mult(&password_raw, &role.my_point());
        let my_msg = (&p + &mask).compress().to_bytes();

        // BoringSSL hashes the identities as `sizeof("...")`, i.e. NUL-terminated.
        let mut my_id = my_id.as_bytes().to_vec();
        my_id.push(0);
        let mut their_id = their_id.as_bytes().to_vec();
        their_id.push(0);
        Self {
            my_id,
            their_id,
            role,
            private,
            password_hash,
            password_raw,
            my_msg,
            their_msg: None,
            dh: None,
            key: None,
        }
    }

    /// The 32-byte message to send (blinded ephemeral point).
    pub fn my_msg(&self) -> &[u8; 32] {
        &self.my_msg
    }

    /// Process the peer's 32-byte message; yields the 64-byte SPAKE2 key.
    pub fn process_msg(&mut self, their_msg: &[u8; 32]) -> Result<[u8; 64]> {
        if self.their_msg.is_some() {
            return Err(anyhow!("their msg already processed"));
        }
        self.their_msg = Some(*their_msg);

        let their_pstar = point_from_bytes(*their_msg)?;
        let their_mask = raw_mult(&self.password_raw, &self.role.their_point());
        let their_p = &their_pstar - &their_mask;

        let dh_point = &their_p * &self.private;
        // BoringSSL puts `x25519_ge_tobytes(dh)` in the transcript, which is the
        // compressed Edwards encoding (y + sign of x), not the Montgomery u.
        let dh = dh_point.compress().to_bytes();
        self.dh = Some(dh);

        let mut t = Vec::with_capacity(256);
        match self.role {
            // BoringSSL: alice hashes (my_name, their_name, my_msg, their_msg)
            // and bob hashes (their_name, my_name, their_msg, my_msg) — both
            // equal to (client_id, server_id, client_msg, server_msg).
            Role::Client => {
                t.extend(lenp(&self.my_id));
                t.extend(lenp(&self.their_id));
                t.extend(lenp(&self.my_msg));
                t.extend(lenp(their_msg));
            }
            Role::Server => {
                t.extend(lenp(&self.their_id));
                t.extend(lenp(&self.my_id));
                t.extend(lenp(their_msg));
                t.extend(lenp(&self.my_msg));
            }
        }
        t.extend(lenp(&dh));
        t.extend(lenp(&self.password_hash));
        let key: [u8; 64] = Sha512::digest(&t).into();
        self.key = Some(key);
        Ok(key)
    }

    /// The 64-byte shared key, once the peer message has been processed.
    pub fn shared_key(&self) -> Option<&[u8; 64]> {
        self.key.as_ref()
    }

    /// The ephemeral private scalar (little-endian 32 bytes), for diagnostics.
    pub fn private_for_debug(&self) -> [u8; 32] {
        self.private.to_bytes()
    }
}

/// Raw little-endian scalar `s` (32 bytes, < 2^256) times group element `p`,
/// as BoringSSL's x25519 ladder does: `s·p = (s mod l)·p + (s div l)·(l·p)`.
///
/// dalek scalars are reduced mod l (`l` itself is the zero scalar), so the
/// `l·Z` term is expanded with `l = 2^252 + c`: `l·Z = 2^252·Z + c·Z`,
/// `c = l - 2^252 < 2^128`.
fn raw_mult(s: &[u8; 32], p: &EdwardsPoint) -> EdwardsPoint {
    const C_LE: [u8; 16] = 27742317777372353535851937790883648493u128.to_le_bytes();
    let (q, r) = div_l(s);
    let mut out = p * &Scalar::from_bytes_mod_order(r);
    if q != 0 {
        let mut z = *p;
        for _ in 1..q {
            z += p;
        }
        let mut lz = z;
        for _ in 0..252 {
            lz = &lz + &lz;
        }
        let mut cb = [0u8; 32];
        cb[..16].copy_from_slice(&C_LE);
        lz += &z * &Scalar::from_bytes_mod_order(cb);
        out += &lz;
    }
    out
}

/// BoringSSL `SPAKE2_generate_msg` password scalar: `s = x25519_sc_reduce`
/// over the **full 64-byte** `SHA512(pw)` (mod l), then the sequential
/// "cofactor hack": for i = 0,1,2, if bit i of the *current* scalar is set,
/// add `2^i · l`. Result ≡ s (mod l), a multiple of 8, and < 8l < 2^256.
///
/// Note: `x25519_sc_reduce` folds the high 32 bytes down, so this is *not*
/// `SHA512(pw)[0..32] mod l`.
fn password_scalar(pw64: &[u8; 64]) -> [u8; 32] {
    use num_bigint::BigUint;
    let l_bytes: Vec<u8> = L.iter().flat_map(|x| x.to_le_bytes()).collect();
    let lv = BigUint::from_bytes_le(&l_bytes);
    let sv = BigUint::from_bytes_le(pw64);
    let mut s = sv % &lv;
    let mut order = lv.clone();
    let two = BigUint::from(2u64);
    for i in 0..3usize {
        if &(&s >> i) % &two != BigUint::from(0u64) {
            s += &order;
        }
        order = &order * &two;
    }
    let mut out = [0u8; 32];
    let pele = s.to_bytes_le();
    let n = pele.len().min(32);
    out[..n].copy_from_slice(&pele[..n]);
    out
}

/// Divide the 32-byte LE integer by l, returning (quotient, 32-byte LE
/// remainder). Quotient is at most 7 for clamped 255-bit values.
fn div_l(s: &[u8; 32]) -> (u64, [u8; 32]) {
    use num_bigint::BigUint;
    use num_traits::ToPrimitive;
    let sv = BigUint::from_bytes_le(s);
    let l_bytes: Vec<u8> = L.iter().flat_map(|x| x.to_le_bytes()).collect();
    let lv = BigUint::from_bytes_le(&l_bytes);
    let q = &sv / &lv;
    let r = &sv % &lv;
    let q64 = q.to_u64().unwrap_or(0);
    let mut rb = [0u8; 32];
    let rle = r.to_bytes_le();
    rb[..rle.len().min(32)].copy_from_slice(&rle[..rle.len().min(32)]);
    (q64, rb)
}

/// `l·p` is not needed as a separate helper: the quotient loop in `raw_mult`
/// accumulates it. Exposed for tests only.
#[allow(dead_code)]
fn l_bytes() -> Vec<u8> {
    L.iter().flat_map(|x| x.to_le_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn fixed_points_are_valid() {
        point_from_bytes(M_POINT).unwrap();
        point_from_bytes(N_POINT).unwrap();
    }

    #[test]
    fn m_and_n_are_distinct() {
        let m = point_from_bytes(M_POINT).unwrap();
        let n = point_from_bytes(N_POINT).unwrap();
        assert_ne!(m, n);
        assert_ne!(m, EdwardsPoint::default());
        assert_ne!(n, EdwardsPoint::default());
    }

    #[test]
    fn div_l_roundtrip() {
        // For a random clamped value s: s == q*l + r with q < 8.
        let mut s = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut s);
        let s = clamp_integer(s);
        let (q, r) = div_l(&s);
        assert!(q < 8);
        // q*l + r == s
        use num_bigint::BigUint;
        let sv = BigUint::from_bytes_le(&s);
        let l_bytes: Vec<u8> = L.iter().flat_map(|x| x.to_le_bytes()).collect();
        let lv = BigUint::from_bytes_le(&l_bytes);
        let recon = BigUint::from(q) * &lv + BigUint::from_bytes_le(&r);
        assert_eq!(recon, sv);
    }

    #[test]
    fn password_scalar_is_multiple_of_8_and_reduced() {
        use num_bigint::BigUint;
        let pw: [u8; 64] = [0x5a; 64];
        let ps = password_scalar(&pw);
        assert_eq!(ps[0] & 7, 0, "ps must be a multiple of 8");
        let l_bytes: Vec<u8> = L.iter().flat_map(|x| x.to_le_bytes()).collect();
        let lv = BigUint::from_bytes_le(&l_bytes);
        let sv = BigUint::from_bytes_le(&pw);
        let ps_v = BigUint::from_bytes_le(&ps);
        assert_eq!(&ps_v % &lv, sv % &lv, "ps ≡ s (mod l)");
    }

    #[test]
    fn raw_mult_matches_dalek_in_subgroup() {
        // For a basepoint multiple (prime-order subgroup) raw mult equals
        // the plain scalar mult.
        let mut s = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut s);
        let s = clamp_integer(s);
        let base = EdwardsPoint::mul_base(&Scalar::from(3u64));
        let a = raw_mult(&s, &base);
        let b = &base * &Scalar::from_bytes_mod_order(s);
        assert_eq!(a, b);
    }

    #[test]
    fn loopback_client_server_agree() {
        let password: Vec<u8> = hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        );
        let mut client = Spake2::new_client(&password);
        let mut server = Spake2::new_server(&password);

        let ckey = client.process_msg(server.my_msg()).expect("client process");
        let skey = server.process_msg(client.my_msg()).expect("server process");
        assert_eq!(ckey, skey, "client and server keys must match");
        assert_eq!(client.shared_key(), Some(&ckey));
        assert_eq!(server.shared_key(), Some(&skey));
    }

    #[test]
    fn different_passwords_fail_to_agree() {
        let mut client = Spake2::new_client(b"password-a");
        let mut server = Spake2::new_server(b"password-b");
        let ckey = client.process_msg(server.my_msg()).unwrap();
        let skey = server.process_msg(client.my_msg()).unwrap();
        assert_ne!(ckey, skey);
    }

    // Reference vectors generated by an independent Python port of BoringSSL's
    // spake25519 (using the ed25519.py referenced in BoringSSL's own source
    // comments). Fixed password and fixed private scalars; the expected
    // messages and 64-byte key must match bit-for-bit.
    #[test]
    fn matches_boringssl_reference_vectors() {
        let mut pw = hex("373736383730"); // "776870"
        pw.extend(std::iter::repeat(0u8).take(64));
        let priv_a = [
            0x90, 0x56, 0xf8, 0x58, 0x67, 0x4c, 0xa5, 0x5a, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let priv_b = [
            0x88, 0x65, 0xb8, 0x1d, 0xc7, 0x3d, 0x84, 0x48, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let msg_a = hex("d0b993d7c4c5589208cb68c4b5d34b52b3823c022fefbe44703f7c92d7bf07f6");
        let msg_b = hex("b34e7db2196c74c1a33b0c6e83b1d4ef63f12de3fcb434a2832c0b3150511792");
        let key = hex("c912ac70d12809f3b039f76f0b83376a1781d79eb376cb94c3f4ffea773a28446e4d2a40423b33d832797fa1c84b29c172ea888eeaa5427ff5996603b06a48f3");

        let mut client = Spake2::with_private(
            CLIENT_ID,
            SERVER_ID,
            Role::Client,
            &pw,
            Scalar::from_bytes_mod_order(priv_a),
        );
        let mut server = Spake2::with_private(
            SERVER_ID,
            CLIENT_ID,
            Role::Server,
            &pw,
            Scalar::from_bytes_mod_order(priv_b),
        );

        assert_eq!(&client.my_msg()[..], &msg_a[..], "client msg mismatch");
        assert_eq!(&server.my_msg()[..], &msg_b[..], "server msg mismatch");

        let ckey: [u8; 64] = client
            .process_msg(msg_b.as_slice().try_into().unwrap())
            .expect("client process")
            .into();
        let skey: [u8; 64] = server
            .process_msg(msg_a.as_slice().try_into().unwrap())
            .expect("server process")
            .into();
        assert_eq!(&ckey.to_vec(), &key[..], "client key mismatch");
        assert_eq!(&skey.to_vec(), &key[..], "server key mismatch");
    }

    #[test]
    fn double_process_rejected() {
        let mut client = Spake2::new_client(b"pw");
        let server = Spake2::new_server(b"pw");
        client.process_msg(server.my_msg()).unwrap();
        assert!(client.process_msg(server.my_msg()).is_err());
    }

    #[test]
    fn basepoint_order_check() {
        let p = &ED25519_BASEPOINT_POINT * &Scalar::from(2u64);
        let q = EdwardsPoint::mul_base(&Scalar::from(2u64));
        assert_eq!(p, q);
    }
}
