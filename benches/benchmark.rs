#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

use aes_gcm::aead::generic_array::{ArrayLength, GenericArray};
use aes_gcm::{
    aead::consts::{U12, U16, U32},
    aead::AeadInPlace,
    aead::KeyInit,
    Aes128Gcm,
};
use benchmark_simple::*;
use chacha20poly1305::ChaCha20Poly1305;
use morus::Morus;
use rand::RngCore;
use rand::{distributions::Uniform, thread_rng, Rng};

const BENCH_ITER: u64 = 100_000;
const BENCH_WARMUP_ITER: u64 = 1000;
const MESSAGE_LENGTH: usize = 16 * 1024;

fn generate_random_vec(data_length: usize) -> Vec<u8> {
    let mut rng = thread_rng();
    let range = Uniform::new(0, u8::MAX);

    (0..data_length).map(|_| rng.sample(range)).collect()
}

struct CipherOptions<KeySize, NonceSize>
where
    KeySize: ArrayLength<u8>,
    NonceSize: ArrayLength<u8>,
{
    key: GenericArray<u8, KeySize>,
    nonce: GenericArray<u8, NonceSize>,
}

impl<KeySize, NonceSize> Default for CipherOptions<KeySize, NonceSize>
where
    KeySize: ArrayLength<u8>,
    NonceSize: ArrayLength<u8>,
{
    fn default() -> Self {
        let mut key = GenericArray::default();
        let mut nonce = GenericArray::default();
        thread_rng().fill_bytes(&mut key);
        thread_rng().fill_bytes(&mut nonce);

        Self { key, nonce }
    }
}

impl<KeySize, NonceSize> CipherOptions<KeySize, NonceSize>
where
    KeySize: ArrayLength<u8>,
    NonceSize: ArrayLength<u8>,
{
    fn as_bytes(&self) -> ([u8; KeySize::USIZE], [u8; NonceSize::USIZE]) {
        let mut key_bytes = [0u8; KeySize::USIZE];
        let mut nonce_bytes = [0u8; NonceSize::USIZE];
        key_bytes.copy_from_slice(&self.key[..]);
        nonce_bytes.copy_from_slice(&self.nonce[..]);

        (key_bytes, nonce_bytes)
    }
}

enum CipherBench {
    Aes128Gcm(CipherOptions<U16, U12>),
    ChaCha20Poly1305(CipherOptions<U32, U12>),
    Morus1280(CipherOptions<U16, U16>),
}

impl CipherBench {
    fn encrypt_detached(
        &self,
        input: &[u8],
        output: &mut [u8],
    ) -> GenericArray<u8, U16> {
        output.copy_from_slice(input);

        match self {
            Self::Aes128Gcm(options) => Aes128Gcm::new(&options.key)
                .encrypt_in_place_detached(&options.nonce, &[], output)
                .unwrap(),
            Self::ChaCha20Poly1305(options) => {
                ChaCha20Poly1305::new(&options.key)
                    .encrypt_in_place_detached(&options.nonce, &[], output)
                    .unwrap()
            }
            Self::Morus1280(options) => {
                let (key, nonce) = options.as_bytes();
                let tag =
                    Morus::new(&nonce, &key).encrypt_in_place(output, &[]);

                tag.into()
            }
        }
    }

    fn decrypt_detached(
        &self,
        tag: &GenericArray<u8, U16>,
        encrypted_input: &[u8],
        decrypted_output: &mut [u8],
    ) {
        decrypted_output.copy_from_slice(encrypted_input);

        match self {
            Self::Aes128Gcm(options) => Aes128Gcm::new(&options.key)
                .decrypt_in_place_detached(
                    &options.nonce,
                    &[],
                    decrypted_output,
                    tag,
                )
                .unwrap(),
            Self::ChaCha20Poly1305(options) => {
                ChaCha20Poly1305::new(&options.key)
                    .decrypt_in_place_detached(
                        &options.nonce,
                        &[],
                        decrypted_output,
                        tag,
                    )
                    .unwrap()
            }
            Self::Morus1280(options) => {
                let (key, nonce) = options.as_bytes();
                let mut tag_array = [0u8; 16];
                tag_array.copy_from_slice(&tag[..]);
                Morus::new(&nonce, &key)
                    .decrypt_in_place(decrypted_output, &tag_array, &[])
                    .unwrap();
            }
        }
    }
}

fn bench_encryption(
    cipher_name: &str,
    bench_options: &Options,
    cipher_options: &CipherBench,
    input: &[u8],
    output: &mut [u8],
) {
    let res = Bench::new().run(bench_options, || {
        cipher_options.encrypt_detached(input, output)
    });
    println!(
        "{:<19} : {}",
        cipher_name,
        res.throughput(MESSAGE_LENGTH as u128)
    );
}

fn bench_decryption(
    cipher_name: &str,
    bench_options: &Options,
    cipher_options: &CipherBench,
    input: &[u8],
    output: &mut [u8],
    tag: &GenericArray<u8, U16>,
) {
    let res = Bench::new().run(bench_options, || {
        cipher_options.decrypt_detached(tag, input, output)
    });
    println!(
        "{:<19} : {}",
        cipher_name,
        res.throughput(MESSAGE_LENGTH as u128)
    );
}

fn main() {
    // Benchmark variables

    let message = generate_random_vec(MESSAGE_LENGTH);
    let aes128gcm_name = "AES128-GCM";
    let chacha20poly1305_name = "CHACHA20-POLY1305";
    let morus1280_name = "MORUS-1280-128";
    let mut aes128gcm_enc_output = vec![0u8; MESSAGE_LENGTH];
    let mut chacha20poly1305_enc_output = vec![0u8; MESSAGE_LENGTH];
    let mut morus1280_enc_output = vec![0u8; MESSAGE_LENGTH];
    let aes128gcm_options = CipherBench::Aes128Gcm(CipherOptions::default());
    let chacha20poly1305_options =
        CipherBench::ChaCha20Poly1305(CipherOptions::default());
    let morus1280_options = CipherBench::Morus1280(CipherOptions::default());
    let bench_options = Options {
        iterations: BENCH_ITER,
        warmup_iterations: BENCH_WARMUP_ITER,
        min_samples: 5,
        max_samples: 10,
        max_rsd: 1.0,
        ..Default::default()
    };

    // Result assertions

    let aes128gcm_enc_tag =
        aes128gcm_options.encrypt_detached(&message, &mut aes128gcm_enc_output);
    let chacha20poly1305_enc_tag = chacha20poly1305_options
        .encrypt_detached(&message, &mut chacha20poly1305_enc_output);
    let morus1280_enc_tag =
        morus1280_options.encrypt_detached(&message, &mut morus1280_enc_output);
    let mut aes128gcm_dec_output = vec![0u8; MESSAGE_LENGTH];
    let mut chacha20poly1305_dec_output = vec![0u8; MESSAGE_LENGTH];
    let mut morus1280_dec_output = vec![0u8; MESSAGE_LENGTH];
    aes128gcm_options.decrypt_detached(
        &aes128gcm_enc_tag,
        &aes128gcm_enc_output,
        &mut aes128gcm_dec_output,
    );
    chacha20poly1305_options.decrypt_detached(
        &chacha20poly1305_enc_tag,
        &chacha20poly1305_enc_output,
        &mut chacha20poly1305_dec_output,
    );
    morus1280_options.decrypt_detached(
        &morus1280_enc_tag,
        &morus1280_enc_output,
        &mut morus1280_dec_output,
    );

    assert_eq!(&message, &aes128gcm_dec_output);
    assert_eq!(&message, &chacha20poly1305_dec_output);
    assert_eq!(&message, &morus1280_dec_output);

    // Benchmark: Encryptions

    println!("\n\x1b[92m[Encryptions]\x1b[0m");

    bench_encryption(
        aes128gcm_name,
        &bench_options,
        &aes128gcm_options,
        &message,
        &mut aes128gcm_enc_output,
    );
    bench_encryption(
        chacha20poly1305_name,
        &bench_options,
        &chacha20poly1305_options,
        &message,
        &mut chacha20poly1305_enc_output,
    );
    bench_encryption(
        morus1280_name,
        &bench_options,
        &morus1280_options,
        &message,
        &mut morus1280_enc_output,
    );

    // Benchmark: Decryptions

    println!("\n\x1b[92m[Decryptions]\x1b[0m");

    bench_decryption(
        aes128gcm_name,
        &bench_options,
        &aes128gcm_options,
        &aes128gcm_enc_output,
        &mut aes128gcm_dec_output,
        &aes128gcm_enc_tag,
    );
    bench_decryption(
        chacha20poly1305_name,
        &bench_options,
        &chacha20poly1305_options,
        &chacha20poly1305_enc_output,
        &mut chacha20poly1305_dec_output,
        &chacha20poly1305_enc_tag,
    );
    bench_decryption(
        morus1280_name,
        &bench_options,
        &morus1280_options,
        &morus1280_enc_output,
        &mut morus1280_dec_output,
        &morus1280_enc_tag,
    );

    // Result re-assertions

    assert_eq!(&message, &aes128gcm_dec_output);
    assert_eq!(&message, &chacha20poly1305_dec_output);
    assert_eq!(&message, &morus1280_dec_output);
}
