use base64::{decode, encode};
use clap::{Arg, ArgGroup, SubCommand};
use libaes::Cipher;
use std::convert::TryInto;
use std::fs::File;
use std::io::{Read, Result, Write};

fn main() {
    let matches = clap::App::new("lau")
        .version("0.1.0")
        .subcommand(
            SubCommand::with_name("encrypt")
                .about("AES 128 encrypt in CBC mode, encrypt -h for more details")
                .arg(
                    Arg::with_name("key")
                        .help("must be 16 characters")
                        .short("k")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("iv")
                        .help("must be 16 characters")
                        .short("i")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("file")
                        .help("file name to read plain text")
                        .short("f")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("message")
                        .help("plain text")
                        .short("m")
                        .takes_value(true),
                )
                .group(
                    ArgGroup::with_name("plaintext")
                        .arg("file")
                        .arg("message")
                        .required(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("decrypt")
                .about("AES 128 decrypt in CBC mode, decrypt -h for more details")
                .arg(
                    Arg::with_name("key")
                        .help("must be 16 characters")
                        .short("k")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("iv")
                        .help("must be 16 characters")
                        .short("i")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("file")
                        .help("file name to read cipher text")
                        .conflicts_with("message")
                        .short("f")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("message")
                        .help("Cipher text in BASE64")
                        .conflicts_with("file")
                        .short("m")
                        .takes_value(true),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        ("encrypt", Some(sub_m)) => {
            let key = sub_m.value_of("key").unwrap();
            if key.len() != libaes::AES_128_KEY_LEN {
                println!("key must be {} characters long", libaes::AES_128_KEY_LEN);
                return;
            }
            let iv = sub_m.value_of("iv").unwrap();
            if iv.len() != 16 {
                println!("iv must be 16 characters long");
                return;
            }
            let key: &[u8; 16] = key.as_bytes().try_into().unwrap();

            if let Some(file_name) = sub_m.value_of("file") {
                let output = encrypt_file(file_name, key, iv.as_bytes()).unwrap();
                println!("Cipher text written into file: {}", &output);
            } else {
                let msg = sub_m.value_of("message").unwrap();
                let cipher = Cipher::new_128(key);
                let cipher_bytes = cipher.cbc_encrypt(iv.as_bytes(), msg.as_bytes());
                println!("Cipher text in BASE64:\n{}", encode(cipher_bytes));
            }
        }
        ("decrypt", Some(sub_m)) => {
            let key = sub_m.value_of("key").unwrap();
            if key.len() != libaes::AES_128_KEY_LEN {
                println!("key must be {} characters long", libaes::AES_128_KEY_LEN);
                return;
            }
            let iv = sub_m.value_of("iv").unwrap();
            if iv.len() != 16 {
                println!("iv must be 16 characters long");
                return;
            }

            // read cipher text from "message" or "file"
            let msg = match sub_m.value_of("message") {
                Some(msg_base64) => match decode(msg_base64) {
                    Ok(m) => m,
                    Err(e) => {
                        println!("Failed to decode Base64: {}", e);
                        return;
                    }
                },
                None => match sub_m.value_of("file") {
                    Some(file_name) => {
                        let mut msg = vec![];
                        match File::open(file_name) {
                            Ok(mut f) => f.read_to_end(&mut msg).unwrap(),
                            Err(e) => {
                                println!("Failed to open file: {}", e);
                                return;
                            }
                        };
                        msg
                    }
                    None => {
                        println!("Missing file name to read cipher text");
                        return;
                    }
                },
            };

            // decrypt the cipher text
            let cipher = Cipher::new_128(key.as_bytes().try_into().unwrap());
            let plain_bytes = cipher.cbc_decrypt(iv.as_bytes(), &msg[..]);
            match std::str::from_utf8(&plain_bytes[..]) {
                Ok(s) => println!("{}", s),
                Err(_) => println!("Plain text is not a string, cannot print it"),
            }
        }
        _ => {}
    }
}

const BLOCK_SIZE: usize = 64 * 1024;

/// Returns the file name of the encrypted.
fn encrypt_file(file_name: &str, key: &[u8; 16], iv: &[u8]) -> Result<String> {
    let mut f = File::open(file_name)?;
    let mut buf = [0; BLOCK_SIZE];

    let out_file_name = format!("{}.encrypted", file_name);
    let mut output_f = File::create(&out_file_name)?;
    let cipher = Cipher::new_128(key);

    loop {
        let n = f.read(&mut buf[..])?;
        if n == 0 {
            break;
        }
        let cipher_text = cipher.cbc_encrypt(iv, &buf[..n]);
        let n = output_f.write(&cipher_text)?;
        if n == 0 {
            println!("cannot write any more");
            break;
        }
    }

    Ok(out_file_name)
}
