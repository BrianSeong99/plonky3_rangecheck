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

pub struct BabyBearRangeCheckBitDecompositionAir<T> {
    // The original value to check.
    pub value: u32,

    // The product of the the bits 3 to 5 in `most_sig_byte_decomp`.
    pub and_most_sig_byte_decomp_4_to_3: T,

    // The product of the the bits 3 to 6 in `most_sig_byte_decomp`.
    pub and_most_sig_byte_decomp_4_to_2: T,

    // The product of the the bits 3 to 7 in `most_sig_byte_decomp`.
    pub and_most_sig_byte_decomp_4_to_1: T,
}

// Baby Bear Modulus in big endian format
// 01111000 00000000 00000000 00000001
impl<F: Field> BaseAir<F> for BabyBearRangeCheckBitDecompositionAir<F> {
    fn width(&self) -> usize {
        32
    }
}


impl<AB: AirBuilder> Air<AB> for BabyBearRangeCheckBitDecompositionAir<AB::F>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let current_row = main.row_slice(0);

        let mut reconstructed_value = AB::Expr::zero();
        for i in 0..32 {
            let bit = current_row[i];
            builder.assert_bool(bit); // Making sure every bit is either 0 or 1
            reconstructed_value += AB::Expr::from_wrapped_u32(1 << (31-i)) * bit; // using `from_wrapped_u32` to make sure the value is in range of 32 bits.
        }

        // Assert if the reconstructed value matches the original value
        builder.when_first_row().assert_eq(AB::Expr::from_wrapped_u32(self.value), reconstructed_value);

        /*:
        The following conditions are used to check that the number is in the range of babybear:
        1. Check if the first bit is zero
        2. Check if all bits from 2nd to 5th are all one, if true, then remaining bits must be zero
        3. Otherwise they can be anything.
        4. Reconstruct the number to compare with the original input.
         */

        // Assert that the most significant bit is zero
        builder.assert_eq(current_row[0], AB::Expr::zero());

        // Value to check if the 2nd to 5th bits are all one
        builder.assert_eq(AB::Expr::from(self.and_most_sig_byte_decomp_4_to_3), current_row[4] * current_row[3]);
        builder.assert_eq(AB::Expr::from(self.and_most_sig_byte_decomp_4_to_2), AB::Expr::from(self.and_most_sig_byte_decomp_4_to_3) * current_row[2]);
        builder.assert_eq(AB::Expr::from(self.and_most_sig_byte_decomp_4_to_1), AB::Expr::from(self.and_most_sig_byte_decomp_4_to_2) * current_row[1]);

        let remaining_bits_sum = current_row[5..32].iter().map(|&bit| bit.into()).sum::<AB::Expr>();

        builder.when(AB::Expr::from(self.and_most_sig_byte_decomp_4_to_1)).assert_zero(remaining_bits_sum);
    }}
pub fn generate_trace_and_inputs<F: Field>(value: u32) -> (RowMajorMatrix<F>, F, F, F) {
    let mut bits = Vec::with_capacity(32); // 32 bits per row
    // Convert the value to binary, in big endian format
    for i in (0..32).rev() {
        if (value & (1 << i)) != 0 {
            bits.push(F::one());
        } else {
            bits.push(F::zero());
        }
    }
    let bits_clone = bits.clone();
    (
        RowMajorMatrix::new(bits, 32), 
        bits_clone[4] * bits_clone[3], 
        bits_clone[4] * bits_clone[3] * bits_clone[2], 
        bits_clone[4] * bits_clone[3] * bits_clone[2] * bits_clone[1]
    )
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
    
    let (trace, and_most_sig_byte_decomp_4_to_3, and_most_sig_byte_decomp_4_to_2, and_most_sig_byte_decomp_4_to_1) = generate_trace_and_inputs::<Val>(value);
    let air = BabyBearRangeCheckBitDecompositionAir { value, and_most_sig_byte_decomp_4_to_3, and_most_sig_byte_decomp_4_to_2, and_most_sig_byte_decomp_4_to_1 };

    let fri_config = FriConfig {
        log_blowup: 1,
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
    let _ = verify(&config, &air, &mut challenger, &proof, &vec![]);
}