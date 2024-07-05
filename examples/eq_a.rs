use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::group::ff::PrimeField;
use halo2_proofs::pasta::{EqAffine, Fp};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column, ConstraintSystem,
    Error, Expression, ProvingKey, Selector, SingleVerifier, VerifyingKey,
};
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::Rotation;
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use rand_core::OsRng;
use std::fs::File;
use std::io::Write;
use std::marker::PhantomData;
use std::path::Path;

// x - a = 0

struct MyCircuit<const VAL: usize, F: PrimeField> {
    value: Value<F>,
    _p: PhantomData<F>,
}

impl<const VAL: usize, F: PrimeField> MyCircuit<VAL, F> {
    fn empty() -> Self {
        MyCircuit {
            value: Value::unknown(),
            _p: PhantomData,
        }
    }

    fn construct(value: u32) -> Self {
        MyCircuit {
            value: Value::known(F::from(value as u64)),
            _p: PhantomData,
        }
    }
}

#[derive(Clone)]
struct MyConfig {
    s: Selector,
    x: Column<Advice>,
}

impl<const VAL: usize, F: PrimeField> Circuit<F> for MyCircuit<VAL, F> {
    type Config = MyConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        todo!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let config = MyConfig {
            s: meta.selector(),
            x: meta.advice_column(),
        };

        meta.create_gate("validator gate", |meta| {
            let selector = meta.query_selector(config.s);
            let a_expr = Expression::Constant(F::from(VAL as u64));
            let x_expr = meta.query_advice(config.x, Rotation::cur());
            // x - a = 0
            vec![selector * (a_expr - x_expr)]
        });

        config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let offset = 0_usize;
        layouter
            .assign_region(
                || "validate region",
                |mut region| {
                    config.s.enable(&mut region, offset).unwrap();
                    let value = self.value.clone();
                    region
                        .assign_advice(|| "adv cell", config.x, offset.clone(), || value)
                        .unwrap();
                    Ok(())
                },
            )
            .unwrap();
        Ok(())
    }
}

// Runs the mock prover and prints any errors
fn run_mock_prover<const VAL: usize>(k: u32, circuit: &MyCircuit<VAL, Fp>) {
    let prover = MockProver::run(k, circuit, vec![]).expect("Mock prover should run");
    let res = prover.verify();
    match res {
        Ok(()) => println!("MockProver OK"),
        Err(e) => println!("err {:#?}", e),
    }
}

fn generate_setup_params(k: u32) -> Params<EqAffine> {
    Params::<EqAffine>::new(k)
}

fn generate_keys<const VAL: usize>(
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
fn generate_proof<const VAL: usize>(
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
