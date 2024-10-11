use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, Field};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use std::marker::PhantomData;

use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_circle::CirclePcs;
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_fri::FriConfig;
use p3_keccak::Keccak256Hash;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_mersenne_31::Mersenne31;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
use p3_uni_stark::{prove, verify, StarkConfig};
use tracing_forest::util::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

pub struct Mersenne31RangeCheckAir {
    pub value: u32,
}

// Mersenne31 Modulus in big endian format
// 01111111 11111111 11111111 11111111
// 2^31 - 1
impl<F: Field> BaseAir<F> for Mersenne31RangeCheckAir {
    fn width(&self) -> usize {
        32 // 1 number per row
    }
}

impl<AB: AirBuilder> Air<AB> for Mersenne31RangeCheckAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let current_row = main.row_slice(0);
        let next_row = main.row_slice(1);

        // Assert that the most significant bit is zero
        builder.when_first_row().assert_eq(current_row[0], AB::Expr::zero());

        let mut reconstructed_value = AB::Expr::zero();
        let mut next_row_rowsum = AB::Expr::zero();
        for i in 0..32 {
            let bit = current_row[i];
            builder.assert_bool(bit); // Making sure every bit is either 0 or 1
            reconstructed_value += AB::Expr::from_wrapped_u32(1 << (31-i)) * bit; // using `from_wrapped_u32` to make sure the value is in range of 31 bits.
            next_row_rowsum += next_row[i].into();
        }

        // Assert if the reconstructed value matches the original value
        builder.when_first_row().assert_eq(AB::Expr::from_wrapped_u32(self.value), reconstructed_value);
        builder.when_transition().assert_eq(next_row_rowsum, AB::Expr::zero());
    }
}

pub fn generate_mersenne31_trace<F: Field>(value: u32) -> RowMajorMatrix<F> {
    let mut bits = Vec::with_capacity(32 * 4); // 32 bits per row, 4 rows, CirclePCS requires 4 rows
    // Convert the value to binary, in big endian format
    for i in (0..32).rev() {
        if (value & (1 << i)) != 0 {
            bits.push(F::one());
        } else {
            bits.push(F::zero());
        }
    }
    for _ in 0..32*3 {
        bits.push(F::zero());
    }
    RowMajorMatrix::new(bits, 32)
}

pub fn prove_and_verify<F: Field>(value: u32) {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .init();

    type Val = Mersenne31;
    type Challenge = BinomialExtensionField<Val, 3>;

    type ByteHash = Keccak256Hash;
    type FieldHash = SerializingHasher32<ByteHash>;
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(Keccak256Hash {});

    type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
    let compress = MyCompress::new(byte_hash);

    type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;
    let val_mmcs = ValMmcs::new(field_hash, compress);

    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;

    let fri_config = FriConfig {
        log_blowup: 1,
        num_queries: 100,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };

    type Pcs = CirclePcs<Val, ValMmcs, ChallengeMmcs>;
    let pcs = Pcs {
        mmcs: val_mmcs,
        fri_config,
        _phantom: PhantomData,
    };

    type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
    let config = MyConfig::new(pcs);

    let air = Mersenne31RangeCheckAir { value };
    let trace = generate_mersenne31_trace::<Val>( value);

    let mut challenger = Challenger::from_hasher(vec![], byte_hash);
    let proof = prove(&config, &air, &mut challenger, trace, &vec![]);

    let mut challenger = Challenger::from_hasher(vec![], byte_hash);
    let _ = verify(&config, &air, &mut challenger, &proof, &vec![]).expect("verification failed");
}