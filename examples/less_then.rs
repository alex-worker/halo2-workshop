// (a - 0)(a - 1)(a - 2) ... (a - (R-1)) = 0

use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::group::ff::PrimeField;
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
use std::marker::PhantomData;

struct MyCircuit<const MAX: usize, F> {
    value: u32,
    _p: PhantomData<F>,
}

impl<const MAX: usize, F> MyCircuit<MAX, F> {
    fn construct(value: u32) -> Self {
        MyCircuit {
            _p: PhantomData,
            value,
        }
    }
}

impl<F: PrimeField, const MAX: usize> Circuit<F> for MyCircuit<MAX, F> {
    type Config = ();
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        todo!()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        todo!()
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<F>) -> Result<(), Error> {
        todo!()
    }
}

fn main() {
    const K: u32 = 6;
    const MAX_VALUE: usize = 6;

    let value: u32 = 5;

    let circuit = MyCircuit::<MAX_VALUE, Fp>::construct(value);

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
    fn test_one() {
        let value = Fp::from(5);
        let circuit = MyCircuit::<MAX_VALUE, Fp>::construct();

        let inputs = vec![value];

        let prover = MockProver::run(K, &circuit, vec![inputs]).unwrap();
        prover.assert_satisfied();
    }
}
