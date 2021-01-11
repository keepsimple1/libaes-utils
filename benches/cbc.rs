use aes::Aes128;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use criterion::{criterion_group, criterion_main, Criterion};
use libaes::Cipher;

/// This bench suite compares the `libaes` crate and `block-modes` + `aes` crates,
/// mainly on `encrypt` and `decrypt` performance for AES128 CBC mode, both using
/// Pkcs7 padding.
///
/// The code using `block-modes` and `aes` mimics the example in their online doc.

// create an alias for convenience
type Aes128Cbc = Cbc<Aes128, Pkcs7>;

const SMALL_PLAIN_TEXT: &[u8; 50] = b"r97dXKLmEOsn4o3ZDDn2xowXG4XblpKuQrbnDvazCYx4O8iNpq";
const SMALL_CIPHER_TEXT: &[u8; 64] =
    b"\x15\x1e\x11\x15\xf5\x0f\x90\x37\xc9\xc6\x2f\x11\x13\xb3\x1c\xa1\
         \x28\x89\x12\xdc\xe6\x4a\xa9\x32\xc8\xa4\x3f\x61\xc4\xcf\x88\xf0\
         \x98\xad\xf1\x02\x2d\xd2\xc8\x06\x51\x00\x5a\x11\x88\x2e\xdb\xc5\
         \x8f\x67\xa9\x09\x68\xfb\x0a\xaa\xfe\xd7\xa7\x69\x6f\x62\x2f\x25";
const SMALL_KEY: &[u8; 16] = b"This is our key!";

fn libaes_128_cbc_encrypt() {
    let iv = b"This is 16 bytes";
    let cipher = Cipher::new_128(SMALL_KEY);
    cipher.cbc_encrypt(iv, SMALL_PLAIN_TEXT);
}

fn libaes_128_cbc_decrypt() {
    let iv = b"This is 16 bytes";
    let cipher = Cipher::new_128(SMALL_KEY);
    let decrypted = cipher.cbc_decrypt(iv, SMALL_CIPHER_TEXT);
    assert_eq!(&decrypted[..], &SMALL_PLAIN_TEXT[..]);
}

fn aes_block_modes_128_cbc_encrypt() {
    let iv = b"This is 16 bytes";
    let cipher = Aes128Cbc::new_var(SMALL_KEY, iv).unwrap();
    cipher.encrypt_vec(SMALL_PLAIN_TEXT);
}

fn aes_block_modes_128_cbc_decrypt() {
    let iv = b"This is 16 bytes";
    let cipher = Aes128Cbc::new_var(SMALL_KEY, iv).unwrap();
    cipher.decrypt_vec(SMALL_CIPHER_TEXT).unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("libaes 128 cbc encrypt", |b| {
        b.iter(|| libaes_128_cbc_encrypt())
    });
    c.bench_function("aes-block-modes 128 cbc encrypt", |b| {
        b.iter(|| aes_block_modes_128_cbc_encrypt())
    });
    c.bench_function("libaes 128 cbc decrypt", |b| {
        b.iter(|| libaes_128_cbc_decrypt())
    });
    c.bench_function("aes-block-modes 128 cbc decrypt", |b| {
        b.iter(|| aes_block_modes_128_cbc_decrypt())
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
