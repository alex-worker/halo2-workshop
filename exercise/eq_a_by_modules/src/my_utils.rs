use crate::my_circuit::MyCircuit;
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Error, ProvingKey, SingleVerifier,
    VerifyingKey,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use rand_core::OsRng;

// Runs the mock prover and prints any errors
pub fn run_mock_prover<const VAL: usize>(k: u32, circuit: &MyCircuit<VAL, Fp>) {
    let prover = MockProver::run(k, circuit, vec![]).expect("Mock prover should run");
    let res = prover.verify();
    match res {
        Ok(()) => println!("MockProver OK"),
        Err(e) => println!("err {:#?}", e),
    }
}

pub fn generate_setup_params(k: u32) -> Params<EqAffine> {
    Params::<EqAffine>::new(k)
}

pub fn generate_keys<const VAL: usize>(
    params: &Params<EqAffine>,
    circuit: &MyCircuit<VAL, Fp>,
) -> (ProvingKey<EqAffine>, VerifyingKey<EqAffine>) {
    // just to emphasize that for vk, pk we don't need to know the value of `x`
    println!("Generating Verification Key");
    let vk = keygen_vk(params, circuit).expect("vk should not fail");
    let pk = keygen_pk(params, vk.clone(), circuit).expect("pk should not fail");
    (pk, vk)
}

// Generates a proof
pub fn generate_proof<const VAL: usize>(
    params: &Params<EqAffine>,
    pk: &ProvingKey<EqAffine>,
    circuit: MyCircuit<VAL, Fp>,
) -> Vec<u8> {
    println!("Generating proof...");
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof(params, pk, &[circuit], &[&[]], OsRng, &mut transcript)
        .expect("Prover should not fail");
    transcript.finalize()
}

// Verifies the proof
pub fn verify(
    params: &Params<EqAffine>,
    vk: &VerifyingKey<EqAffine>,
    proof: Vec<u8>,
) -> Result<(), Error> {
    println!("Verifying proof...");
    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    verify_proof(params, vk, strategy, &[&[]], &mut transcript)
}
