# b2b

[![Build Status](https://travis-ci.org/metadave/b2b.svg?branch=master)](https://travis-ci.org/metadave/b2b)


`b2b` is a command line tool to calculate [BLAKE2b](https://blake2.net/)  hashes based on [libsodium](https://github.com/jedisct1/libsodium) and [sodiumoxide](https://github.com/dnaq/sodiumoxide).

```
b2b 0.1.0
Dave Parfitt <diparfitt@gmail.com>
Calculates BLAKE2b checksums using libsodium

USAGE:
    b2b [FLAGS] [OPTIONS] <FILE>

FLAGS:
        --base64     Display the value in RFC 4648 standard base64 encoding instead of hex
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -l, --length <HASH_LENGTH>    Size of hash in bytes, default: 32

ARGS:
    <FILE>    Input filename or - to read from <stdin>
```

# Building from source

b2b is written in [Rust](https://www.rust-lang.org/).


### Ubuntu

TODO: untested

```
apt-get install libsodium-dev
cargo build
```

### OSX

```
brew install libsodium
export SODIUM_LIB_DIR=`brew info libsodium | grep Cellar | awk '{ print $1 }'`/lib
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$SODIUM_LIB_DIR
cargo build
```

# Dependency notes

This tool depends on sodiumoxide and the `crypto_generichash_*` functions which were recently merged, but do not appear in the higher level `sodiumoxide` API. Because of this, there is a `.cargo/config` hack to use an vendored version of sodiumoxide in the `vendor` directory. As soon as sodiumoxide has higher level API's and publishes a new crate, I'll take this magic out which will allow `cargo install b2b` to work.

# License

b2b is released under the [Apache 2](http://www.apache.org/licenses/LICENSE-2.0.html) license.

See also:

- https://github.com/jedisct1/libsodium/blob/master/LICENSE

- https://github.com/dnaq/sodiumoxide/blob/master/LICENSE

---

© 2016 Dave Parfitt
