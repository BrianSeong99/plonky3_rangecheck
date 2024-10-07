use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, Field};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_goldilocks::Goldilocks;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_keccak::Keccak256Hash;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher64};
use p3_uni_stark::{prove, verify, StarkConfig};
use tracing_forest::util::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

pub struct GoldilocksRangeCheckAir {
    pub value: u64,
}

// Goldilocks Modulus in big endian format:
// 11111111 11111111 11111111 11111111 00000000 00000000 00000000 00000001
// 2^64 - 2^32 + 1
impl<F: Field> BaseAir<F> for GoldilocksRangeCheckAir {
    fn width(&self) -> usize {
        64
    }
}

impl<AB: AirBuilder> Air<AB> for GoldilocksRangeCheckAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let current_row = main.row_slice(0);

        /*:
        The following conditions are used to check that the number is in the range of Goldilocks:
        1. Check if all bits from 1st to 32nd are all one, if true, then remaining bits must be zero
        2. Otherwise they can be anything.
        3. Reconstruct the number to compare with the original input.
         */

        // Value to check if the 1st to 32nd bits are all one
        let upper_bits_product = current_row[0..32].iter().map(|&bit| bit.into()).product::<AB::Expr>();
        let remaining_bits_sum = current_row[32..64].iter().map(|&bit| bit.into()).sum::<AB::Expr>();
        
        builder.when(upper_bits_product.clone()).assert_zero(remaining_bits_sum);

        let mut reconstructed_value = AB::Expr::zero();
        for i in 0..64 {
            let bit = current_row[i];
            builder.assert_bool(bit); // Making sure every bit is either 0 or 1
            reconstructed_value += AB::Expr::from_wrapped_u64(1 << (63-i)) * bit; // using `from_wrapped_u64` to make sure the value is in range of 64 bits.
        }

        // Assert if the reconstructed value matches the original value
        builder.when_first_row().assert_eq(AB::Expr::from_wrapped_u64(self.value), reconstructed_value);
    }
}


pub fn generate_trace<F: Field>(value: u64) -> RowMajorMatrix<F> {
    let mut bits = Vec::with_capacity(64);
    for i in (0..64).rev() {
        if (value & (1 << i)) != 0 {
            bits.push(F::one());
        } else {
            bits.push(F::zero());
        }
    }
    
    // Pad the trace matrix to the next power of 2
    let next_power_of_two = bits.len().next_power_of_two();
    bits.resize(next_power_of_two, F::zero());
    
    RowMajorMatrix::new(bits, next_power_of_two)
}

pub fn prove_and_verify<F: Field>(value: u64) {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .init();

    type Val = Goldilocks;
    type Challenge = BinomialExtensionField<Val, 2>;

    type ByteHash = Keccak256Hash;
    type FieldHash = SerializingHasher64<ByteHash>;
    let byte_hash = ByteHash {};
    let field_hash = FieldHash::new(byte_hash);

    type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
    let compress = MyCompress::new(byte_hash);

    type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;
    let val_mmcs = ValMmcs::new(field_hash, compress);

    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    type Dft = Radix2DitParallel<Val>;
    let dft = Dft::default();

    type Challenger = SerializingChallenger64<Val, HashChallenger<u8, ByteHash, 32>>;

    let fri_config = FriConfig {
        log_blowup: 5,
        num_queries: 100,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
    let pcs = Pcs::new(dft, val_mmcs, fri_config);

    type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
    let config = MyConfig::new(pcs);

    let air = GoldilocksRangeCheckAir { value };
    let trace = generate_trace::<Val>(value);

    let mut challenger = Challenger::from_hasher(vec![], byte_hash);
    let proof = prove(&config, &air, &mut challenger, trace, &vec![]);

    let mut challenger = Challenger::from_hasher(vec![], byte_hash);
    let _ = verify(&config, &air, &mut challenger, &proof, &vec![]);
}
