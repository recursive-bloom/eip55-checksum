
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use tiny_keccak::{Keccak, Hasher};
use hex::encode;

/****

https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md
./target/debug/eip55checksum 0x3a7b653e26f54e4a579237a15893e13a4bdd3451
./target/debug/eip55checksum 3a7b653e26f54e4a579237a15893e13a4bdd3451

ref: https://github.com/miguelmota/rust-eth-checksum
ref: https://github.com/mcaveniathor/eth-rs
ls

 ****/


fn main() {
    let args: Vec<String> = std::env::args().collect();
    //println!("{}", eth_checksum_encode("0x3a7b653e26f54e4a579237a15893e13a4bdd3451"));
    let addr = eip_55_encode(&args[1]);
    println!("eip-55: {}", addr);
    println!("valid:  {}", validate_eip_55("0x3a7b653e26f54e4a579237a15893e13a4bdd3451"));
    println!("valid:  {}", validate_eip_55("0x3a7b653E26f54E4A579237A15893E13A4bDD3451"));
    let x = "0x3a7b653E26f54E4A579237A15893E13A4bDD3451".to_ascii_lowercase();
    let y = x.trim_start_matches("0x");
    let foo = y.as_bytes();
    println!("foo = {:X?}", foo);
    let z = String::from(y);
    //let z = String::from(x.trim_start_matches("0x"));
    let te = z.as_bytes();
    println!("{:X?}", keccak256_vec(te));
    println!("{:x?}", keccak256_vec(te));

}

fn keccak256_vec(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut output: [u8; 32] = Default::default();
    hasher.finalize(&mut output);
    output.iter().cloned().collect()
}

pub fn keccak256_array(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

fn validate_eip_55(address: &str) -> bool {
    let check = eip_55_encode(&address);
    address == check
}


fn eip_55_encode(address: &str) -> String {
    let input = String::from(address.to_ascii_lowercase().trim_start_matches("0x"));
    println!("input:  0x{}", input);
    let mut hasher = Sha3::keccak256();
    hasher.input_str(&input);
    let hash = hasher.result_str();
    println!("hash:   0x{}", hash);
    let mut ret = String::with_capacity(42);
    ret.push_str("0x");
    for i in 0..40 {
        if u32::from_str_radix(&hash[i..i+1], 16).unwrap() >= 8 {
            ret.push_str(&input[i..i+1].to_ascii_uppercase()); 
        } else {
            ret.push_str(&input[i..i+1]);
        }
    }
    println!("result: {}", ret);
    ret
}

fn eip_55_adress_validate(address: &str) -> bool {
    let check = eip_55_address_checksum(address);
    check == address
}

fn eip_55_address_checksum(address: &str) -> String {
    let input = String::from(address.to_ascii_lowercase().trim_start_matches("0x"));
    let hash = hex::encode(keccak256_array(input.as_bytes()));
    let mut ret = String::with_capacity(42);
    ret.push_str("0x");
    for i in 0..40 {
        if u32::from_str_radix(&hash[i..i+1], 16).unwrap() >= 8 {
            ret.push_str(&input[i..i+1].to_ascii_uppercase());
        } else {
            ret.push_str(&input[i..i+1]);
        }
    }
    ret
}


#[test]
fn test() {
    println!("{:?}", u32::from_str_radix("A", 16).unwrap());
    println!("{:?}", u32::from_str_radix("A", 16));
    assert_eq!(u32::from_str_radix("A", 16), Ok(10));

    println!("{}", eip_55_address_checksum("0x3a7b653e26f54e4a579237a15893e13a4bdd3451"));
    assert!(eip_55_adress_validate("0x3a7b653E26f54E4A579237A15893E13A4bDD3451"));

    println!("{}", eip_55_address_checksum("0xe0fc04fa2d34a66b779fd5cee748268032a146c0"));
    assert!(eip_55_adress_validate("0xe0FC04FA2d34a66B779fd5CEe748268032a146c0"));
}

