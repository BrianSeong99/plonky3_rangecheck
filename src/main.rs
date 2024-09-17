use std::fmt::Debug;

use clap::{Command, Arg};

mod rc_m31_m31_keccak;
mod rc_babybear_babybear_poseidon2_ver1;
mod rc_goldilocks_goldilocks_sha256_ver1;

fn main() -> Result<(), Box<dyn Debug>> {
    use p3_mersenne_31::Mersenne31;
    use p3_baby_bear::BabyBear;
    use p3_goldilocks::Goldilocks;
    use crate::rc_m31_m31_keccak as rc_m31;
    use crate::rc_babybear_babybear_poseidon2_ver1 as rc_babybear_v1;
    use crate::rc_goldilocks_goldilocks_sha256_ver1 as rc_goldilocks_v1;

    let matches = Command::new("Range Check")
        .arg(
            Arg::new("function")
                .short('f')
                .long("function")
                .value_name("FUNCTION")
                .help("Range check function to use")
                .value_parser(["mersenne31", "babybear_v1", "babybear_v2", "goldilocks_v1"])
                .required(true),
        )
        .arg(
            Arg::new("value")
                .short('v')
                .long("value")
                .value_name("VALUE")
                .help("Input value to check")
                .required(true),
        )
        .get_matches();

    let function = matches.get_one::<String>("function").unwrap();
    let value = matches
        .get_one::<String>("value")
        .unwrap()
        .parse::<u64>()
        .expect("Invalid input value");


    match function.as_str() {
        "mersenne31" => {
            if value > u64::from(u32::MAX) {
                panic!("Input value is not u32");
            }
            let value = value as u32;
            rc_m31::prove_and_verify::<Mersenne31>(value);
        }
        "babybear_v1" => {
            if value > u64::from(u32::MAX) {
                panic!("Input value is not u32");
            }
            let value = value as u32;
            rc_babybear_v1::prove_and_verify::<BabyBear>(value);
        }
        "goldilocks_v1" => {
            if value > u64::MAX {
                panic!("Input value is not u64");
            }
            let value = value as u64;
            rc_goldilocks_v1::prove_and_verify::<Goldilocks>(value);
        }
        _ => unreachable!(),
    }

    Ok(())
}