use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::group::ff::PrimeField;
use halo2_proofs::pasta::{vesta, EqAffine, Fp};
use halo2_proofs::plonk::{
    create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column, ConstraintSystem,
    Error, Expression, Selector, SingleVerifier,
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

struct MyCircuit<const VAL: usize, F> {
    value: u32,
    _p: PhantomData<F>,
}

impl<const VAL: usize, F> MyCircuit<VAL, F> {
    fn construct(value: u32) -> Self {
        MyCircuit {
            value,
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
                    let value = Value::known(F::from(self.value.clone() as u64));
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

const K: u32 = 3;

fn main() {
    let params: Params<EqAffine> = halo2_proofs::poly::commitment::Params::new(K);

    let circuit = MyCircuit::<8, Fp>::construct(8);

    println!("Generating Verification Key");
    let vk = keygen_vk(&params, &circuit).unwrap();

    // Generate proving key.
    println!("Generating Proving Key from Verification Key");
    let pk = keygen_pk(&params, vk, &circuit).unwrap();
    let vk = pk.get_vk();

    let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);

    println!("Generating Proof!");
    create_proof(
        &params,
        &pk,
        &[circuit],
        &[&[]],
        &mut OsRng,
        &mut transcript,
    )
    .expect("Failed to create proof!");

    let proof_path = "./proof";
    let proof = transcript.finalize();

    println!("Verifying proof...");
    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

    verify_proof(&params, vk, strategy, &[&[]], &mut transcript).unwrap();

    // File::create(Path::new(proof_path))
    //     .expect("Failed to create proof file")
    //     .write_all(&proof[..])
    //     .expect("Failed to write proof");
    // println!("Proof written to: {}", proof_path);

    // const VALUE: usize = 8;
    //
    // // x - VALUE = 0
    //
    // let circuit = MyCircuit::<VALUE, Fp>::construct(8);
    //
    // let prover = MockProver::<Fp>::run(K, &circuit, vec![]).unwrap();
    // assert!(prover.verify().is_ok());
    //
    // let circuit = MyCircuit::<VALUE, Fp>::construct(10);
    //
    // let prover = MockProver::<Fp>::run(K, &circuit, vec![]).unwrap();
    // assert!(prover.verify().is_err());
}

#[cfg(test)]
mod tests {
    use crate::MyCircuit;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::pasta::Fp;

    const K: u32 = 3;

    #[test]
    fn test_ok() {
        let circuit = MyCircuit::<8, Fp>::construct(10);
        let prover = MockProver::<Fp>::run(K, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_error() {
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
