// x - a = 0

use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::pasta::group::ff::PrimeField;
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Selector};
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

pub struct MyCircuit<const VAL: usize, F: PrimeField> {
    value: Value<F>,
    _p: PhantomData<F>,
}

impl<const VAL: usize, F: PrimeField> MyCircuit<VAL, F> {
    pub fn empty() -> Self {
        MyCircuit {
            value: Value::unknown(),
            _p: PhantomData,
        }
    }

    pub fn construct(value: u32) -> Self {
        MyCircuit {
            value: Value::known(F::from(value as u64)),
            _p: PhantomData,
        }
    }
}

#[derive(Clone)]
pub struct MyConfig {
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
