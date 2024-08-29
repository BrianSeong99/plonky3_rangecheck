use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, Field};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{prove, verify, StarkConfig};
use rand::thread_rng;
use tracing_forest::util::LevelFilter;
use tracing_forest::ForestLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

pub struct BabyBearRangeCheckAir {
    pub value: u32,
}

// Baby Bear Modulus in big endian format 01111000 00000000 00000000 00000001
impl<F: Field> BaseAir<F> for BabyBearRangeCheckAir {
    fn width(&self) -> usize {
        32
    }
}

impl<AB: AirBuilder> Air<AB> for BabyBearRangeCheckAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let current_row = main.row_slice(0);

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
        let upper_bits_product = current_row[1..5].iter().map(|&bit| bit.into()).product::<AB::Expr>();
        let bottom_bits_sum = current_row[5..8].iter().map(|&bit| bit.into()).sum::<AB::Expr>();
        let remaining_bits_sum = current_row[8..32].iter().map(|&bit | bit.into()).sum::<AB::Expr>();
        
        builder.when(upper_bits_product.clone()).assert_zero(bottom_bits_sum);
        builder.when(upper_bits_product.clone()).assert_zero(remaining_bits_sum);

        let mut reconstructed_value = AB::Expr::zero();
        for i in 0..32 {
            let bit = current_row[i];
            builder.assert_bool(bit); // Making sure every bit is either 0 or 1
            reconstructed_value += AB::Expr::from_wrapped_u32(1 << (31-i)) * bit; // using `from_wrapped_u32` to make sure the value is in range of 31 bits.
        }

        // Assert if the reconstructed value matches the original value
        builder.when_first_row().assert_eq(AB::Expr::from_wrapped_u32(self.value), reconstructed_value);
    }}

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

    type Perm = Poseidon2<Val, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>;
    let perm = Perm::new_from_rng_128(
        Poseidon2ExternalMatrixGeneral,
        DiffusionMatrixBabyBear::default(),
        &mut thread_rng(),
    );

    type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
    let hash = MyHash::new(perm.clone());

    type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
    let compress = MyCompress::new(perm.clone());

    type ValMmcs = FieldMerkleTreeMmcs<
        <Val as Field>::Packing,
        <Val as Field>::Packing,
        MyHash,
        MyCompress,
        8,
    >;
    let val_mmcs = ValMmcs::new(hash, compress);

    type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

    type Dft = Radix2DitParallel;
    let dft = Dft {};

    type Challenger = DuplexChallenger<Val, Perm, 16, 8>;

    let fri_config = FriConfig {
        log_blowup: 2,
        num_queries: 100,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
    let pcs = Pcs::new(dft, val_mmcs, fri_config);

    type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
    let config = MyConfig::new(pcs);

    let air = BabyBearRangeCheckAir { value };
    let trace = generate_trace::<Val>( value);

    let mut challenger = Challenger::new(perm.clone());
    let proof = prove(&config, &air, &mut challenger, trace, &vec![]);

    let mut challenger = Challenger::new(perm);
    let _ = verify(&config, &air, &mut challenger, &proof, &vec![]);
}