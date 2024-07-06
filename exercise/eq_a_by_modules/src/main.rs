mod my_circuit;
mod my_utils;

use crate::my_circuit::MyCircuit;
use crate::my_utils::{
    generate_keys, generate_proof, generate_setup_params, run_mock_prover, verify,
};

use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::poly::commitment::Params;

use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
    const K: u32 = 3;

    let proof: Vec<u8>;

    const VALUE: usize = 8;

    // create circuit  f(value) = VALUE
    // verify with mock prover
    // create ProvingKey from circuit
    // generate proof
    {
        let value = 8;
        let params: Params<EqAffine> = generate_setup_params(K);
        let circuit = MyCircuit::<VALUE, Fp>::construct(value);
        run_mock_prover(K, &circuit);

        let (pk, _) = generate_keys(&params, &circuit);
        proof = generate_proof(&params, &pk, circuit);
    }

    // save proof to disk
    {
        let proof_path = "./proof";
        File::create(Path::new(proof_path))
            .expect("Failed to create proof file")
            .write_all(&proof[..])
            .expect("Failed to write proof");
        println!("Proof written to: {}", proof_path);
    }

    // create circuit  f(?) = VALUE
    // generate VerifyingKey from circuit
    // verifying proof
    {
        let params: Params<EqAffine> = generate_setup_params(K);
        let circuit = MyCircuit::<VALUE, Fp>::empty();

        let (_, vk) = generate_keys(&params, &circuit);
        verify(&params, &vk, proof).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use crate::MyCircuit;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::pasta::Fp;

    const K: u32 = 3;

    #[test]
    fn test_error() {
        let circuit = MyCircuit::<8, Fp>::construct(10);
        let prover = MockProver::<Fp>::run(K, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_ok() {
        let circuit = MyCircuit::<10, Fp>::construct(10);
        let prover = MockProver::<Fp>::run(K, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_zero() {
        let circuit = MyCircuit::<0, Fp>::construct(0);
        let prover = MockProver::<Fp>::run(K, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }
}
