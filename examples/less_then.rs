// (a - 0)(a - 1)(a - 2) ... (a - (R-1)) = 0
// R = 3, a = 2 => (2 - 2)

use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::group::ff::PrimeField;
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk;
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Selector};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

#[derive(Clone)]
struct MyConfig {
    s: Selector,
    x: Column<Advice>,
}

struct MyCircuit<const MAX: usize, F> {
    value: u32,
    _p: PhantomData<F>,
}

impl<const MAX: usize, F> MyCircuit<MAX, F> {
    fn new(value: u32) -> Self {
        MyCircuit {
            _p: PhantomData,
            value,
        }
    }
}

impl<F: PrimeField, const MAX: usize> Circuit<F> for MyCircuit<MAX, F> {
    type Config = MyConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        todo!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let conf = MyConfig {
            s: meta.selector(),
            x: meta.advice_column(),
        };
        meta.create_gate("validator gate", |meta| {
            let selector = meta.query_selector(conf.s);
            let a = meta.query_advice(conf.x, Rotation::cur());
            let acc = (0..MAX)
                .enumerate()
                .try_fold(a.clone(), |mut acc, (_, i)| {
                    let expression = a.clone() - Expression::Constant(F::from(i as u64));
                    acc = acc * expression;
                    Result::<_, plonk::Error>::Ok(acc)
                })
                .expect("TODO: panic message");
            vec![selector * acc]
        });
        conf
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let offset = 0_usize;
        let value = Value::known(F::from(self.value.clone() as u64));
        layouter
            .assign_region(
                || "",
                |mut region| {
                    config.s.enable(&mut region, offset.clone())?;
                    region.assign_advice(|| "input", config.x, offset, || value)?;
                    Ok(())
                },
            )
            .unwrap();
        Ok(())
    }
}

fn main() {
    const K: u32 = 6;
    const MAX_VALUE: usize = 6;
    let value: u32 = 5;

    let circuit = MyCircuit::<MAX_VALUE, Fp>::new(value);
    let prover = MockProver::<Fp>::run(K, &circuit, vec![]).unwrap();
    prover.assert_satisfied();
}

#[cfg(test)]
mod tests {
    use crate::MyCircuit;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::pasta::Fp;

    const K: u32 = 6;
    const MAX_VALUE: usize = 6;

    #[test]
    fn test_zero_zero() {
        let value: u32 = 0;

        let circuit = MyCircuit::<0, Fp>::new(value);
        let prover = MockProver::<Fp>::run(K, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_1_zero() {
        let value: u32 = 1;

        let circuit = MyCircuit::<0, Fp>::new(value);
        let prover = MockProver::<Fp>::run(K, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_less() {
        let value: u32 = 5;

        let circuit = MyCircuit::<MAX_VALUE, Fp>::new(value);
        let prover = MockProver::<Fp>::run(K, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_more() {
        let value: u32 = 6;

        let circuit = MyCircuit::<MAX_VALUE, Fp>::new(value);
        let prover = MockProver::<Fp>::run(K, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }

    #[test]
    fn test_equal() {
        let value: u32 = MAX_VALUE as u32;

        let circuit = MyCircuit::<MAX_VALUE, Fp>::new(value);
        let prover = MockProver::<Fp>::run(K, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }
}
