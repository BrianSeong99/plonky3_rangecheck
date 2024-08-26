use std::fmt::Debug;

use clap::{Command, Arg};

mod rc_m31;

fn main() -> Result<(), Box<dyn Debug>> {
    use p3_mersenne_31::Mersenne31;
    use crate::rc_m31 as rc_m31;

    let matches = Command::new("Range Check")
        .arg(
            Arg::new("function")
                .short('f')
                .long("function")
                .value_name("FUNCTION")
                .help("Range check function to use")
                .value_parser(["mersenne31"])
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
        _ => unreachable!(),
    }

    Ok(())
}