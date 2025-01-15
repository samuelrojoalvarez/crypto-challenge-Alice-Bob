# crypto-challenge-Alice-Bob

This repository contains a challenge demonstrating an **elliptic-curve Diffie-Hellman (ECDH)** implementation **over an RSA modulus** $`n = p \times q`$ 
Below is an in-depth analysis of why this scheme is insecure, how to break it, and how to fix it using **standard elliptic-curve cryptography** suitable for **blockchain security** environments.
Alice and Bob use this scheme to derive a shared secret and then encrypt a message with AES-CBC.

The code looks like a typical ECC-based key exchange, but:

  - The modulus 𝑛 is composite $`n = p \times q`$.
  - Standard ECC is intended for prime fields **𝐹$`p`$**(or binary fields	​**𝐹$`2m`$**), not composite moduli.

As a result, an attacker who can factor 𝑛 can exploit the structure to recover the private keys (or directly the shared secret) and decrypt the message.


---

## Table of Contents
1. [Overview](#overview)  
2. [Why ECC Over $`n = p  \times q`$ Is Insecure](#why-ecc-over-n--p--q-is-insecure)   
3. [Step-by-Step Break (Recovering the Secret)](#step-by-step-break-recovering-the-secret)  
4. [A Secure Rewrite (Standard ECC)](#a-secure-rewrite-standard-ecc)  
5. [Conclusion](#conclusion)  
6. [Rust-Based Alternative Solution](#rust-based-alternative-solution)

---

## 1. Overview

- **Original Code**: `rsa_dh.py` implements a naive ECDH over a composite modulus $`n = p \times q`$.  
- **Vulnerability**: In standard ECC, we work in **𝐹$`p`$** where \(p\) is prime. With a composite \(n\), an attacker can:
  1. Factor $`n`$ into $`p`$ and $`q`$.
  2. Solve discrete logs in smaller fields **𝐹$`p`$**  and **𝐹$`𝑞`$** .
  3. Combine results via the Chinese Remainder Theorem (CRT).  
  4. Recover the shared secret and thus decrypt any message.

- **Goal**: Demonstrate:
  1. **Why** the scheme is insecure.
  2. **How** to perform the attack to recover the secret.
  3. **A proper ECDH** approach for secure blockchain communications (e.g., using secp256k1).

---

## 2. Why ECC Over n = p x q Is Insecure

### 1. Composite Modulus
Elliptic-curve operations become **bimodal**: one can “split” them into **𝐹$`p`$** and **𝐹$`𝑞`$**. This is **not** how standard ECC is intended to work.

### 2. Factorization Leads to Discrete Logs
Once \(n\) is factored:
1. Reduce the base point \(G\) and public keys \((X, Y)\) **mod \(p\)** and **mod \(q\)**.  
2. Solve **two** smaller elliptic-curve discrete-log problems.  
3. Rebuild the original private key via **CRT**.

### 3. Breaking the Scheme
The combined knowledge of these two partial solutions yields the **full** private key, allowing an attacker to **recompute** the shared secret and decrypt the message.

---

## 3. Step-by-Step Break (Recovering the Secret)

Below is **pseudocode** illustrating how an attacker can recover the secret. It **mirrors** the original `rsa_dh.py` operations but factors \(n\) and solves discrete logs in each prime field.

```python
#!/usr/bin/env python3


#break_rsa_dh.py

#1) Factor n into p and q
#2) Solve ECC discrete log in F_p and F_q
#3) Rebuild private key with CRT
#4) Derive shared secret and decrypt*#


import hashlib
from math import gcd
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def add(P, Q, E):
    # Same group law from rsa_dh.py, but we can reduce mod p or q as needed
    n, A = E
    X1, Y1 = P
    X2, Y2 = Q

    if (X1, Y1) == (0,0):
        return (X2, Y2)
    if (X2, Y2) == (0,0):
        return (X1, Y1)

    double = (X1 == X2) and ((Y1 + Y2) % n != 0)
    if double:
        # point doubling
        num = (3 * X1**2 + A) % n
        den = (2 * Y1) % n
        l = (num * pow(den, -1, n)) % n
    else:
        # point addition
        dx = (X2 - X1) % n
        dy = (Y2 - Y1) % n
        l = (dy * pow(dx, -1, n)) % n

    X3 = (l*l - X1 - X2) % n
    Y3 = (l*(X1 - X3) - Y1) % n
    return (X3, Y3)

def mul(k, P, E):
    # Scalar multiplication from rsa_dh.py
    R = (0,0)
    Q = P
    for bit in bin(k)[2:][::-1]:
        if bit == '1':
            R = add(R, Q, E)
        Q = add(Q, Q, E)
    return R

def factor_n(n):
    #Factor n = p*q using some factoring approach.
    #(Placeholder for real factorization method.)


    # e.g., Pollard's Rho or advanced factoring library.
    raise NotImplementedError("Implement or call factoring method here.")

def solve_discrete_log(base_point, public_point, prime_mod, A):
    #Solve discrete log in the elliptic curve mod prime_mod.
    #This might use baby-step giant-step or Pollard's Rho for ECC.

    raise NotImplementedError("Implement ECC discrete log here.")

def solve_crt(x_p, x_q, m_p, m_q):
    #Solve:
    #  x ≡ x_p (mod m_p)
    #  x ≡ x_q (mod m_q)
    
    M = m_p * m_q
    M1 = M // m_p
    M2 = M // m_q
    inv1 = pow(M1, -1, m_p)
    inv2 = pow(M2, -1, m_q)
    return (x_p*M1*inv1 + x_q*M2*inv2) % M

def break_rsa_dh(n, A, G, order, alice_pub, bob_pub, enc):
    # 1. Factor n => p, q
    p, q = factor_n(n)

    # 2. Reduce curve params mod p, mod q
    Ap = A % p
    Aq = A % q
    Gp, Gq = (G[0] % p, G[1] % p), (G[0] % q, G[1] % q)
    alice_pub_p = (alice_pub[0] % p, alice_pub[1] % p)
    alice_pub_q = (alice_pub[0] % q, alice_pub[1] % q)

    # 3. Solve for alice_priv in each prime field
    alice_priv_mod_p = solve_discrete_log(Gp, alice_pub_p, p, Ap)
    alice_priv_mod_q = solve_discrete_log(Gq, alice_pub_q, q, Aq)

    # 4. Combine partial keys with CRT => alice_priv_full
    #    Typically modulo (p-1) and (q-1), or the respective group orders.
    alice_priv_full = solve_crt(alice_priv_mod_p, alice_priv_mod_q, p-1, q-1)

    # 5. Recompute shared secret: mul(alice_priv_full, bob_pub, E=(n,A))
    shared_secret = mul(alice_priv_full, bob_pub, (n, A))

    # 6. Decrypt ciphertext
    ciphertext_hex, iv_hex = enc
    ciphertext = bytes.fromhex(ciphertext_hex)
    iv = bytes.fromhex(iv_hex)

    key = hashlib.sha256(str(shared_secret).encode()).digest()
    aes = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(aes.decrypt(ciphertext), 16)

    print("[+] Recovered plaintext:", plaintext)
    return plaintext
```
**Result:** Once it factor 𝑛 and solve the discrete logs in each smaller field, recovering the message is factoring + ECC discrete log from scratch (which is a major undertaking), we could do in a CTF enviroment:

  · Integrate a factoring library (e.g., GGNFS, or in Rust using rug or symcrypt).
  · Implement a standard discrete-log algorithm (e.g., Pollard’s Rho for ECC)..

## 4. A Secure Rewrite (Standard ECC)
Below is a minimal example of a secure ECDH flow with secp256k1, the curve used in Bitcoin/Ethereum, along with AES encryption. This is typically how key exchange is done in blockchain projects.
```python
#!/usr/bin/env python3


#secure_ecdh.py

#Secure ECDH on secp256k1,
#plus AES encryption of a message.


import os, hashlib
from eth_keys import keys  # pip install eth-keys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def derive_ecdh_key(priv_int, peer_pub):
    
    #ECDH on secp256k1:
    #Return the x-coordinate of (priv_int * peer_pub).
    
    priv_key_obj = keys.PrivateKey(priv_int.to_bytes(32, 'big'))
    # eth_keys doesn't have direct ECDH, but it's possible to do:
    shared_point = priv_key_obj.public_key.ecdsa_curve.multiply(
        point=peer_pub.to_bytes(),
        scalar=priv_int
    )
    x_bytes = shared_point[0].to_bytes(32, 'big')
    return x_bytes

def main():
    # 1. Generate ephemeral private keys
    alice_priv_int = int.from_bytes(os.urandom(32), 'big') % keys.curves.SECP256k1.order
    bob_priv_int   = int.from_bytes(os.urandom(32), 'big') % keys.curves.SECP256k1.order

    # 2. Corresponding public keys
    alice_pub = keys.PrivateKey(alice_priv_int.to_bytes(32, 'big')).public_key
    bob_pub   = keys.PrivateKey(bob_priv_int.to_bytes(32, 'big')).public_key

    # 3. Derive ECDH shared secret
    alice_secret = derive_ecdh_key(alice_priv_int, bob_pub)
    bob_secret   = derive_ecdh_key(bob_priv_int, alice_pub)
    assert alice_secret == bob_secret, "ECDH mismatch!"

    # 4. Derive an AES key from the shared secret
    aes_key = hashlib.sha256(alice_secret).digest()

    # 5. Encrypt a message
    message = b"Hello, blockchain world!"
    iv = os.urandom(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(message, 16))

    print("[*] Ciphertext (hex):", ciphertext.hex())
    print("[*] IV (hex):", iv.hex())

    # 6. Bob decrypts
    decipher = AES.new(aes_key, AES.MODE_CBC, iv)
    recovered = unpad(decipher.decrypt(ciphertext), 16)
    print("[*] Recovered message:", recovered)

if __name__ == "__main__":
    main()
```
> [!NOTE]
> **Why This is Secure??**
> 1. secp256k1 is a standard, well-reviewed curve over a prime field,There is no known sub-exponential-time algorithm to solve the discrete log problem. The best-known methods (e.g., Pollard’s Rho) still >require on the order of 𝑛 operations, where 𝑛 ≈ 2^256.
> 2. The ECDH operation is done properly, deriving only the x-coordinate as the shared secret.
> 3. A cryptographic hash (SHA-256) is applied to produce the AES key.
> 4. No steps rely on insecure or “homebrew” group laws over composite moduli.]
> 5. AES: We rely on robust encryption (AES-256-CBC) with random IV.
> 6. Hash / KDF: We do not directly use the raw point (𝑥,𝑦) as the key but hash the x-coordinate. In production, an HKDF with domain separation (“ECDH v1” or “Bitcoin-labeled KDF”) is recommended to avoid possible side-channel or key-composition issues.


## 5. Conclusion
**· Insecure Implementation:** ECC over $`n = p \times q`$ is flawed; factoring 𝑛 splits the problem into smaller prime fields, making discrete log attacks feasible.

**· Breaking the Scheme:** Factor  𝑛, solve partial discrete logs in **𝐹$`p`$**  and **𝐹$`𝑞`$**, apply CRT, then decrypt.

**· Secure Rewrite:** Use standard prime-field ECC (e.g. secp256k1 or secp256r1). Derive keys with ECDH and a robust KDF (e.g., HKDF over SHA-256), and encrypt with a strong AEAD mode (AES-GCM or ChaCha20-Poly1305) in production for secure message encryption in blockchain contexts.

## 6. Rust based Alternative Solution

**Cargo.toml**
```
[package]
name = "my-rust-ecdh"
version = "0.1.0"
edition = "2021"

[dependencies]
# For factoring (this is just an example; there are various crates)
# "rug" or "num-bigint" can handle large integers.
num-bigint = "0.4"
num-integer = "0.1"
num-traits = "0.2"

# For block ciphers and modes
aes = "0.8"
block-modes = "0.8"
# This provides AES CBC with PKCS#7
[dependencies.block-modes]
version = "0.8"
features = ["aes", "pkcs7"]

# For hashing
sha2 = "0.10"

# For random number generation
rand = "0.8"

# For a secp256k1-based ECDH solution
k256 = "0.11"   # or rust-secp256k1, etc.
```

**main.rs**

```rust
//! Demonstrates:
//! 1) Breaking ECC over n = p*q by factoring n and solving discrete logs mod p, q.
//! 2) A secure ECDH approach on secp256k1 (common in blockchain).

use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use num_bigint::{BigInt, RandPrime, ToBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::{thread_rng, RngCore};
use sha2::{Digest, Sha256};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

fn main() {
    // Part 1: Demonstrate how the "insecure" system can be broken
    break_insecure_ec_example();

    // Part 2: Demonstrate a "secure" ECDH approach with secp256k1
    secure_ecdh_example();
}

////////////////////////////////////////////////////////////////
// 1) BREAKING ECC OVER COMPOSITE n
////////////////////////////////////////////////////////////////

fn break_insecure_ec_example() {
    println!("=== PART 1: BREAKING ECC OVER COMPOSITE n ===");

    // For demonstration, let's pretend we have the following "challenge" data:
    // (In a real scenario, these might be much larger.)
    let p = gen_prime(128); 
    let q = gen_prime(128);
    let n = &p * &q;
    
    // Big "A" parameter from original code (example). 
    let a_hex = "1115160ded643518fc0b46ad430da8e5c15f85fe03d0b6b181060f8c167714c650b31b4850b2f06430903acabcee293a8f88eb2a94554636fe823e6b6e753f7de3b6436b32518715df94030bf910993d5158cf47c83042e3fff16181819155f4";
    let a = BigInt::parse_bytes(a_hex.as_bytes(), 16).unwrap();
    
    // Fake G point, Alice, Bob pub keys, etc.
    let g = (BigInt::from(5), BigInt::from(7));
    let alice_pub = (BigInt::from(123), BigInt::from(456));
    let bob_pub = (BigInt::from(789), BigInt::from(111));
    
    // "Encrypted" message (ciphertext, iv):
    let ciphertext_hex = "c60e342afb987f8d..."; // truncated
    let iv_hex = "1e3ea9e079af6467...";        // truncated

    // 1. Factor n
    let (factored_p, factored_q) = factor_n(n).expect("Factorization failed");

    // 2. Solve discrete logs mod p and mod q (stub)
    let alice_priv_mod_p = BigInt::from(42);
    let alice_priv_mod_q = BigInt::from(99);

    // 3. Combine with CRT
    let alice_priv_full = crt_combine(
        &alice_priv_mod_p, &(p.clone() - BigInt::one()),
        &alice_priv_mod_q, &(q.clone() - BigInt::one())
    );

    // 4. Recompute shared_secret
    let shared_secret = mul_ec_composite(&alice_priv_full, &bob_pub, n, &a);

    // 5. Decrypt
    let recovered_msg = decrypt_with_shared_secret(
        &shared_secret, ciphertext_hex, iv_hex
    );

    println!("[+] Recovered message: {}", recovered_msg);
    println!("==================================================\n");
}

/// Naive factor function for demonstration only.
fn factor_n(n: &BigInt) -> Option<(BigInt, BigInt)> {
    let mut i = BigInt::from(2);
    while &i * &i <= *n {
        if n.is_multiple_of(&i) {
            let q = n / &i;
            return Some((i, q));
        }
        i += BigInt::one();
    }
    None
}

/// Solve CRT for x:
///   x ≡ x_p (mod m_p)
///   x ≡ x_q (mod m_q)
fn crt_combine(x_p: &BigInt, m_p: &BigInt, x_q: &BigInt, m_q: &BigInt) -> BigInt {
    let mp_mq = m_p * m_q;

    let mp_inv = mod_inverse(&(mp_mq.clone() / m_p), m_p).unwrap();
    let mq_inv = mod_inverse(&(mp_mq.clone() / m_q), m_q).unwrap();

    let part1 = x_p * (mp_mq.clone() / m_p.clone()) * mp_inv;
    let part2 = x_q * (mp_mq.clone() / m_q.clone()) * mq_inv;

    (part1 + part2) % mp_mq
}

/// Extended Euclidean Algorithm for GCD and inverses
fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if b.is_zero() {
        return (a.clone(), BigInt::one(), BigInt::zero());
    }
    let (g, x1, y1) = extended_gcd(b, &(a % b));
    (g, y1.clone(), x1 - (a / b) * y1)
}

/// Compute modular inverse
fn mod_inverse(a: &BigInt, m: &BigInt) -> Option<BigInt> {
    let (g, x, _) = extended_gcd(a, m);
    if g.is_one() {
        Some((x % m + m) % m)
    } else {
        None
    }
}

/// Generate a prime of given bits (small demonstration prime)
fn gen_prime(bits: u64) -> BigInt {
    let mut rng = thread_rng();
    rng.gen_prime(bits).to_bigint().unwrap()
}

/// Elliptic curve "mul" function over composite n = p*q (demonstration only).
fn mul_ec_composite(k: &BigInt, point: &(BigInt, BigInt), n: &BigInt, a: &BigInt) -> (BigInt, BigInt) {
    let mut result = (BigInt::zero(), BigInt::zero());
    let mut q = point.clone();
    let mut k_bin = k.clone();

    while k_bin > BigInt::zero() {
        if &k_bin & BigInt::one() == BigInt::one() {
            result = add_ec_composite(&result, &q, n, a);
        }
        q = add_ec_composite(&q, &q, n, a);
        k_bin >>= 1;
    }
    result
}

/// Elliptic curve "add" over composite n
fn add_ec_composite(
    p1: &(BigInt, BigInt),
    p2: &(BigInt, BigInt),
    n: &BigInt,
    a: &BigInt
) -> (BigInt, BigInt) {
    let (x1, y1) = p1;
    let (x2, y2) = p2;

    if x1.is_zero() && y1.is_zero() {
        return (x2.clone(), y2.clone());
    }
    if x2.is_zero() && y2.is_zero() {
        return (x1.clone(), y1.clone());
    }

    let lam = if x1 == x2 {
        if (&y1 + y2) % n == BigInt::zero() {
            return (BigInt::zero(), BigInt::zero());
        }
        let numerator = (BigInt::from(3) * x1 * x1 + a) % n;
        let denominator = (BigInt::from(2) * y1) % n;
        let inv_denom = mod_inverse(&denominator, n).unwrap();
        (numerator * inv_denom) % n
    } else {
        let dy = (&y2 - y1) % n;
        let dx = (&x2 - x1) % n;
        let inv_dx = mod_inverse(&dx, n).unwrap();
        (dy * inv_dx) % n
    };

    let x3 = ((&lam * &lam) - x1 - x2) % n;
    let y3 = ((&lam * (x1 - &x3)) - y1) % n;

    ((x3 + n) % n, (y3 + n) % n)
}

/// Decrypt using shared_secret hashed with SHA-256
fn decrypt_with_shared_secret(
    shared_secret: &(BigInt, BigInt),
    ciphertext_hex: &str,
    iv_hex: &str
) -> String {
    let secret_str = format!("{:?}", shared_secret);
    let mut hasher = Sha256::new();
    hasher.update(secret_str.as_bytes());
    let key = hasher.finalize();

    let ciphertext = hex_to_bytes(ciphertext_hex);
    let iv = hex_to_bytes(iv_hex);

    let cipher = Aes256Cbc::new_from_slices(&key, &iv).unwrap();
    let decrypted_data = cipher.decrypt_vec(&ciphertext).unwrap();
    String::from_utf8_lossy(&decrypted_data).to_string()
}

fn hex_to_bytes(hex_str: &str) -> Vec<u8> {
    (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i+2], 16).unwrap())
        .collect()
}

////////////////////////////////////////////////////////////////
// 2) A SECURE ECDH APPROACH (BLOCKCHAIN: secp256k1)
////////////////////////////////////////////////////////////////

use k256::{
    ecdh::{EphemeralSecret, SharedSecret},
    EncodedPoint, PublicKey as K256PublicKey,
    SecretKey as K256SecretKey,
};

fn secure_ecdh_example() {
    println!("=== PART 2: SECURE ECDH (secp256k1) ===");

    // 1. Generate ephemeral secret keys
    let alice_secret = EphemeralSecret::random(&mut thread_rng());
    let bob_secret = EphemeralSecret::random(&mut thread_rng());

    // 2. Corresponding public keys
    let alice_public = K256PublicKey::from(&alice_secret);
    let bob_public   = K256PublicKey::from(&bob_secret);

    // 3. Each derive the shared secret
    let alice_shared = alice_secret.diffie_hellman(&bob_public);
    let bob_shared   = bob_secret.diffie_hellman(&alice_public);
    assert_eq!(
        alice_shared.as_bytes(),
        bob_shared.as_bytes(),
        "ECDH mismatch!"
    );

    // 4. Create an AES key by hashing the shared secret
    let mut hasher = Sha256::new();
    hasher.update(alice_shared.as_bytes());
    let aes_key = hasher.finalize();

    // 5. Encrypt a message with AES-256-CBC
    let mut iv = [0u8; 16];
    thread_rng().fill_bytes(&mut iv);
    let cipher = Aes256Cbc::new_from_slices(&aes_key, &iv).unwrap();

    let message = b"Hello from secp256k1 in Rust!";
    let ciphertext = cipher.encrypt_vec(message);

    println!("[*] Ciphertext (hex): {}", hex::encode(&ciphertext));
    println!("[*] IV (hex): {}", hex::encode(&iv));

    // 6. Bob decrypts
    let cipher = Aes256Cbc::new_from_slices(&aes_key, &iv).unwrap();
    let recovered = cipher.decrypt_vec(&ciphertext).unwrap();
    println!("[*] Recovered message: {}", String::from_utf8_lossy(&recovered));

    println!("==================================================\n");
}
```
