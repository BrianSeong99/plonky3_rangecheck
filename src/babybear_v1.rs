use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, Field};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_monty_31::dft::RecursiveDft;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
use p3_uni_stark::{prove, verify, StarkConfig};
use tracing_forest::util::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

pub struct BabyBearRangeCheckAir {
    pub value: u32, // define constraint input, value is assigned to check against the reconstructed value.
}

// Baby Bear Modulus in big endian format
// 01111000 00000000 00000000 00000001
impl<F: Field> BaseAir<F> for BabyBearRangeCheckAir {
    fn width(&self) -> usize {
        32
    }
}

impl<AB: AirBuilder> Air<AB> for BabyBearRangeCheckAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let current_row = main.row_slice(0);

        // Assert that the most significant bit is zero
        builder.assert_eq(current_row[0], AB::Expr::zero());

        // Value to check if the 2nd to 5th bits are all one
        let upper_bits_product = current_row[1..5].iter().map(|&bit| bit.into()).product::<AB::Expr>();
        // Value to check if the sum of the remaining bits is zero, only if `upper_bits_product` is 1.
        let remaining_bits_sum = current_row[5..32].iter().map(|&bit | bit.into()).sum::<AB::Expr>();
        
        // Assert if the 2nd to 5th bits are all one, then `remaining_bits_sum` has to be zero.
        builder.when(upper_bits_product.clone()).assert_zero(remaining_bits_sum);

        // initializing the `reconstructed_value`
        let mut reconstructed_value = AB::Expr::zero();
        for i in 0..32 {
            let bit = current_row[i];
            // Making sure every bit is either 0 or 1
            builder.assert_bool(bit); 
            reconstructed_value += AB::Expr::from_wrapped_u32(1 << (31-i)) * bit; // using `from_wrapped_u32` to make sure the value is in range of 32 bits.
        }

        // Assert if the reconstructed value matches the original value
        builder.when_first_row().assert_eq(AB::Expr::from_wrapped_u32(self.value), reconstructed_value);
    }
}

pub fn generate_trace<F: Field>(value: u32) -> RowMajorMatrix<F> {
    let mut bits = Vec::with_capacity(32); // 32 bits per row
    // Convert the value to binary, in big endian format
    for i in (0..32).rev() {
        if (value & (1 << i)) != 0 {
            bits.push(F::one());
        } else {
            bits.push(F::zero());
        }
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

    type Val = BabyBear;
    type Challenge = BinomialExtensionField<Val, 4>;

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

    let air = BabyBearRangeCheckAir { value };
    let trace = generate_trace::<Val>( value);

    let fri_config = FriConfig {
        log_blowup: 2,
        num_queries: 100,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    type Dft = RecursiveDft<Val>;
    let dft = Dft::new(trace.height() << fri_config.log_blowup);

    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
    let pcs = Pcs::new(dft, val_mmcs, fri_config);

    type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
    let config = MyConfig::new(pcs);

    let mut challenger = Challenger::from_hasher(vec![], byte_hash);
    let proof = prove(&config, &air, &mut challenger, trace, &vec![]);

    let mut challenger = Challenger::from_hasher(vec![], byte_hash);
    let _ = verify(&config, &air, &mut challenger, &proof, &vec![]).expect("verification failed");
}