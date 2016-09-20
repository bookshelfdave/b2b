// Copyright 2016 Dave Parfitt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

extern crate clap;
extern crate libsodium_sys;
extern crate rustc_serialize;
extern crate sodiumoxide;

use std::fs::File;
use std::io::prelude::*;
use std::io;
use std::io::BufReader;
use std::mem;
use std::path::Path;
use std::ptr;
use std::result;

use clap::{Arg, App};
use rustc_serialize::base64::{STANDARD, ToBase64};
use rustc_serialize::hex::ToHex;
use sodiumoxide::init as nacl_init;

// brew install libsodium
// brew info libsodium | grep Cellar | awk '{ print $1 }'
// export SODIUM_LIB_DIR=/usr/local/Cellar/libsodium/1.0.8/lib/
// export LD_LIBRARY_PATH=/usr/local/Cellar/libsodium/1.0.8/lib/
//

const BUF_SIZE: usize = 1024;

pub fn hash_file<P: AsRef<Path>>(filename: &P, len: usize) -> Result<Vec<u8>, io::Error> {
    let file = try!(File::open(filename.as_ref()));
    let mut reader = BufReader::new(file);
    hash_reader(&mut reader, len)
}


/// Hey, this function is pretty terrible. When there is a higher level
/// interface to the crypto_generichash_* stuff in sodiumoxide, then
/// I'll rip it out and make it prettier.
/// See also: https://download.libsodium.org/doc/hashing/generic_hashing.html
pub fn hash_reader<T: Read>(reader: &mut BufReader<T>, len: usize) -> Result<Vec<u8>, io::Error> {
    let mut out = [0u8; 512 / 8];
    let mut st = vec![0u8; (unsafe { libsodium_sys::crypto_generichash_statebytes() })];
    let pst = unsafe {
        mem::transmute::<*mut u8, *mut libsodium_sys::crypto_generichash_state>(st.as_mut_ptr())
    };

    unsafe {
        libsodium_sys::crypto_generichash_init(pst, ptr::null_mut(), 0, len / 8);
    }

    let mut buf = [0u8; BUF_SIZE];
    loop {
        let bytes_read = try!(reader.read(&mut buf));
        if bytes_read == 0 {
            break;
        }
        let chunk = &buf[0..bytes_read];
        unsafe {
            libsodium_sys::crypto_generichash_update(pst, chunk.as_ptr(), chunk.len() as u64);
        }
    }
    unsafe {
        libsodium_sys::crypto_generichash_final(pst, out.as_mut_ptr(), len / 8);
    }
    let vout: Vec<u8> = From::from(&out[..len / 8]);
    Ok(vout)
}


/// Does the file passed in from the CLI exist?
fn file_exists(val: String) -> result::Result<(), String> {
    if Path::new(&val).is_file() {
        Ok(())
    } else {
        Err(format!("File: '{}' cannot be found", &val))
    }
}

/// Does the file passed in from the CLI exist,
/// OR did the user pass in `-` to indicate stdin.
fn file_exists_or_stdin(val: String) -> result::Result<(), String> {
    if val == "-" {
        Ok(())
    } else {
        file_exists(val)
    }
}

fn valid_hash_length(val: String) -> result::Result<(), String> {
    let v: u32 = val.parse().ok().expect("Hash length isn't a number");
    match v {
        8 | 16 | 32 | 64 | 128 | 256 | 512 => Ok(()),
        _ => Err("Length must be one of 8, 16, 32, 64, 128, 256, 512".to_string()),
    }
}

fn main() {
    let matches = App::new("b2b")
                      .version("0.1.0")
                      .author("Dave Parfitt <diparfitt@gmail.com>")
                      .about("Calculates a BLAKE2b checksums as hex")
                      .arg(Arg::with_name("file")
                               .value_name("FILE")
                               .help("Input filename or - to read from <stdin>")
                               .required(true)
                               .validator(file_exists_or_stdin))
                      .arg(Arg::with_name("hash_length")
                               .value_name("HASH_LENGTH")
                               .long("length")
                               .short("l")
                               .help("Size of hash in bytes, default: 32")
                               .validator(valid_hash_length))
                      .arg(Arg::with_name("base64")
                               .long("base64")
                               .help("Display the value in RFC 4648 standard base64 encoding instead of hex"))
                      .get_matches();
    let infile = matches.value_of("file").unwrap();

    let hash_length = matches.value_of("hash_length").unwrap_or("32");
    let hash_length: usize = hash_length.parse().ok().expect("Invalid hash length");

    nacl_init();

    if infile == "-" {
        // checksum stdin
        let mut reader = BufReader::new(io::stdin());
        match hash_reader(&mut reader, hash_length) {
            Ok(result) => {
                if matches.occurrences_of("base64") > 0 {
                    println!("{}", &result.to_base64(STANDARD));
                } else {
                    println!("{}", &result.to_hex());
                }
            }
            Err(e) => println!("Error calculating checksum {}", e),
        }
    } else {
        // checksum a file
        let p = Path::new(infile);
        let fname = match p.to_str() {
            Some(f) => f,
            None => panic!("Can't parse input filename")
        };
        match hash_file(&p, hash_length) {
            Ok(result) => {
                if matches.occurrences_of("base64") > 0 {
                    println!("{} {}", &result.to_base64(STANDARD), fname);
                } else {
                    println!("{} {}", &result.to_hex(), fname);
                }
            }
            Err(e) => {
                println!("Error calculating checksum {}", e);
            }
        }
    };

}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::path::PathBuf;
    use rustc_serialize::hex::ToHex;

    pub fn exe_path() -> PathBuf {
        env::current_exe().unwrap()
    }

    pub fn license() -> PathBuf {
        exe_path().parent().unwrap().parent().unwrap().parent().unwrap().join("LICENSE")
    }

    // Running b2sum against the LICENSE file int the project root produces
    // the following sums:
    // root@733ceb451f14:/src/foo/BLAKE2/b2sum# ./b2sum -l 8 ./LICENSE
    // 60  ./LICENSE
    // root@733ceb451f14:/src/foo/BLAKE2/b2sum# ./b2sum -l 16 ./LICENSE
    // 9c42  ./LICENSE
    // root@733ceb451f14:/src/foo/BLAKE2/b2sum# ./b2sum -l 32 ./LICENSE
    // fc77e894  ./LICENSE
    // root@733ceb451f14:/src/foo/BLAKE2/b2sum# ./b2sum -l 64 ./LICENSE
    // 9d056c8b6b5b1f65  ./LICENSE
    // root@733ceb451f14:/src/foo/BLAKE2/b2sum# ./b2sum -l 128 ./LICENSE
    // 006bcba112c5398fa8bfc03627d88038  ./LICENSE
    // root@733ceb451f14:/src/foo/BLAKE2/b2sum# ./b2sum -l 256 ./LICENSE
    // aa3b61bd2c008faac2104660b98dcf503a20ec75d9aaa9b90a1751ec05171d94  ./LICENSE
    // root@733ceb451f14:/src/foo/BLAKE2/b2sum# ./b2sum -l 512 ./LICENSE
    // 9936066fe0b25df84b0ae86bfdf5a8fa2da2e0f70b41fb32c7941fef5de105b47b36f1860c8143f4786a51926b1774d09e4f11e87c3069e36733f6d22bb97271  ./LICENSE

    #[test]
    fn test_checksums() {
        let l = license();
        assert!(hash_file(&l, 8).unwrap().as_slice().to_hex() == "60");
        assert!(hash_file(&l, 16).unwrap().as_slice().to_hex() == "9c42");
        assert!(hash_file(&l, 32).unwrap().as_slice().to_hex() == "fc77e894");
        assert!(hash_file(&l, 64).unwrap().as_slice().to_hex() == "9d056c8b6b5b1f65");
        assert!(hash_file(&l, 128).unwrap().as_slice().to_hex() ==
                "006bcba112c5398fa8bfc03627d88038");
        assert!(hash_file(&l, 256).unwrap().as_slice().to_hex() ==
                "aa3b61bd2c008faac2104660b98dcf503a20ec75d9aaa9b90a1751ec05171d94");
        assert!(hash_file(&l, 512).unwrap().as_slice().to_hex() ==
                "9936066fe0b25df84b0ae86bfdf5a8fa2da2e0f70b41fb32c7941fef5de105b47b36f1860c8143f4786a51926b1774d09e4f11e87c3069e36733f6d22bb97271");


    }


}
