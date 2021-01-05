# libaes-utils
Utils using libaes

## Encrypt and decrypt using libaes

```text
USAGE:
    libaes-utils [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    decrypt    AES 128 decrypt in CBC mode, decrypt -h for more details
    encrypt    AES 128 encrypt in CBC mode, encrypt -h for more details
    help       Prints this message or the help of the given subcommand(s)
```

Encrypt:

```text
$ target/debug/libaes-utils encrypt -h
libaes-utils-encrypt
AES 128 encrypt in CBC mode, encrypt -h for more details

USAGE:
    libaes-utils encrypt [OPTIONS] -i <iv> -k <key> -m <message>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -f <file>           file name to write cipher text
    -i <iv>             must be 16 characters
    -k <key>            must be 16 characters
    -m <message>        plain text
```

Decrypt:

```text
$ target/debug/libaes-utils decrypt -h
libaes-utils-decrypt
AES 128 decrypt in CBC mode, decrypt -h for more details

USAGE:
    libaes-utils decrypt -f <file> -i <iv> -k <key> -m <message>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -f <file>           file name to read cipher text
    -i <iv>             must be 16 characters
    -k <key>            must be 16 characters
    -m <message>        Cipher text in BASE64
```

## Benchmark libaes

We run benchmark testing with `libaes` against `RustCrypto` crates `aes` + `block-modes`.

The current result on MacBook Pro Mid-2015 with Rust 1.49:

`cargo bench`

Result summary:
```text
libaes 128 cbc encrypt  time:   [639.89 ns 641.24 ns 642.72 ns]
aes-block-modes 128 cbc encrypt
                        time:   [2.2069 us 2.2125 us 2.2193 us]

libaes 128 cbc decrypt  time:   [664.92 ns 679.57 ns 696.55 ns]
aes-block-modes 128 cbc decrypt
                        time:   [2.4734 us 2.4985 us 2.5264 us]
```

For AES-128 CBC mode, `libaes` is more than 300% faster than `aes` + `block-modes`.
