use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    pasta::group::ff::PrimeField,
    plonk::{self, Advice, Circuit, Column, ConstraintSystem, Expression, Selector, TableColumn},
    poly::Rotation,
};

// f(x) = (-x * (81 * x - 3281)) / 1640
// f(0) = 0
// f(40) =
// f(41) =

// Sets the circuit, and also stores the private input
pub struct BracketCircuit<const MAX_SIZE: usize, F: PrimeField> {
    input: [char; MAX_SIZE],
    _p: PhantomData<F>,
}

impl<const MAX_SIZE: usize, F: PrimeField> BracketCircuit<MAX_SIZE, F> {
    pub fn new(input_str: &[char]) -> Self {
        let mut input: [char; MAX_SIZE] = [0 as char; MAX_SIZE];
        // assert!(input_str.len() <= MAX_SIZE);
        if input_str.len() >= MAX_SIZE {
            panic!("Length {:?} > MAX_SIZE {:}", input_str.len(), MAX_SIZE);
        }
        input[0..input_str.len()].clone_from_slice(input_str);
        Self {
            input,
            _p: PhantomData,
        }
    }
}

// Stores the configuration of the table (columns) that the circuit needs
#[derive(Clone)]
pub struct Config {
    s_input: Selector,
    s_not_minus_one: Selector,
    s_is_accum_zero: Selector,
    // For input
    input: Column<Advice>,
    // For allowed ASCII codes
    allowed: TableColumn,
    accum: Column<Advice>,
    inverted_accum_plus_1: Column<Advice>,
}

impl<const L: usize, F: PrimeField> Circuit<F> for BracketCircuit<L, F> {
    type Config = Config;

    // Not important at this stage
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        todo!("Not needed at this stage.")
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let config = Config {
            s_input: meta.selector(),
            s_is_accum_zero: meta.selector(),
            s_not_minus_one: meta.selector(),
            input: meta.advice_column(),
            accum: meta.advice_column(),
            inverted_accum_plus_1: meta.advice_column(),
            allowed: meta.lookup_table_column(),
        };

        // f(x) = 81 - 2 * x
        // f(x) = (-x * (81 * x - 3281)) / 1640
        meta.create_gate("accumulation", |meta| {
            let _81 = Expression::Constant(F::from(81));
            let _2 = Expression::Constant(F::from(2));
            let _3281 = Expression::Constant(F::from(3281));
            let _1640_inv = Expression::Constant(F::from(1640).invert().unwrap_or_else(|| F::ZERO));

            let s_input = meta.query_selector(config.s_input);
            let s_is_accum_zero = meta.query_selector(config.s_is_accum_zero);
            let x = meta.query_advice(config.input, Rotation::cur());
            let prev = meta.query_advice(config.accum, Rotation::cur());
            let result = meta.query_advice(config.accum, Rotation::next());

            let expression = (-x.clone() * (_81 * x - _3281)) * _1640_inv - result;

            vec![
                s_input * (prev.clone() + expression),
                s_is_accum_zero * prev,
            ]
        });

        meta.create_gate("check_accum", |meta| {
            let _1 = Expression::Constant(F::ONE);

            let s = meta.query_selector(config.s_not_minus_one);
            let accum = meta.query_advice(config.accum, Rotation::cur());
            let inv_x = meta.query_advice(config.inverted_accum_plus_1, Rotation::cur());

            let x = accum + _1.clone();

            let gate1 = _1 - (x.clone() * inv_x);
            let gate2 = x * gate1.clone();

            vec![s.clone() * gate1, s * gate2]
        });

        meta.lookup(|table| {
            let input = table.query_advice(config.input, Rotation::cur());

            vec![(input, config.allowed)]
        });

        config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), plonk::Error> {
        layouter.assign_table(
            || "allowed",
            |mut table| {
                table.assign_cell(|| "empty", config.allowed, 0, || Value::known(F::ZERO))?;
                table.assign_cell(
                    || "(",
                    config.allowed,
                    1,
                    || Value::known(F::from('(' as u64)),
                )?;
                table.assign_cell(
                    || ")",
                    config.allowed,
                    2,
                    || Value::known(F::from(')' as u64)),
                )?;

                Ok(())
            },
        )?;

        layouter.assign_region(
            || "accumulatior and process region",
            |mut region| {
                let _81 = Value::known(F::from(81 as u64));
                let _2 = Value::known(F::from(2 as u64));
                let _3281 = Value::known(F::from(3281 as u64));
                let _1640_inv =
                    Value::known(F::from(1640 as u64).invert().unwrap_or_else(|| F::ZERO));

                let prev =
                    region.assign_advice(|| "accum", config.accum, 0, || Value::known(F::ZERO))?;

                region.assign_advice(
                    || "inverted accum",
                    config.inverted_accum_plus_1,
                    0,
                    || prev.value().map(|val| val.add(F::ONE).invert().unwrap()),
                )?;
                config.s_not_minus_one.enable(&mut region, 0)?;

                self.input
                    .iter()
                    .map(|input_symbol| Value::known(F::from(*input_symbol as u64)))
                    .enumerate()
                    .try_fold(prev.value().copied(), |prev, (offset, input_symbol)| {
                        config.s_input.enable(&mut region, offset)?;

                        region.assign_advice(|| "input", config.input, offset, || input_symbol)?;
                        // f(x) = 81 - 2 * x
                        // f(x) = (-x * (81 * x - 3281)) / 1640

                        // let acc_value = _81 - (_2 * sym) + prev;
                        let acc_value = (-input_symbol.clone() * (_81 * input_symbol - _3281))
                            * _1640_inv
                            + prev;

                        config.s_not_minus_one.enable(&mut region, offset + 1)?;
                        region.assign_advice(|| "accum", config.accum, offset + 1, || acc_value)?;
                        region.assign_advice(
                            || "inv_accum",
                            config.inverted_accum_plus_1,
                            offset + 1,
                            || acc_value.map(|v| v.add(F::ONE).invert().unwrap_or_else(|| F::ZERO)),
                        )?;

                        Result::<_, plonk::Error>::Ok(acc_value)
                    })?;

                // config.s_is_accum_zero.enable(&mut region, L)?;

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{dev::MockProver, pasta::Fq};

    use super::*;

    const K: u32 = 10;

    const ZERO_CHAR: char = 0 as char;
    const MAX_LENGTH: usize = 10;

    #[test]
    fn unvalid_last_accum_open() {
        let input_str = ['(', '(', ')'];
        MockProver::run(
            K,
            &BracketCircuit::<MAX_LENGTH, Fq>::new(&input_str),
            vec![],
        )
        .unwrap()
        .verify()
        .unwrap_err();
    }

    #[test]
    fn unvalid_last_accum_close() {
        let input_str = ['(', ')', ')'];
        MockProver::run(
            K,
            &BracketCircuit::<MAX_LENGTH, Fq>::new(&input_str),
            vec![],
        )
        .unwrap()
        .verify()
        .unwrap_err();
    }

    #[test]
    fn unvalid_sym() {
        let input_str = ['*'];
        MockProver::run(
            K,
            &BracketCircuit::<MAX_LENGTH, Fq>::new(&input_str),
            vec![],
        )
        .unwrap()
        .verify()
        .unwrap_err();
    }

    #[test]
    fn valid_1() {
        let input_str = ['(', ')'];
        let r = MockProver::run(
            K,
            &BracketCircuit::<MAX_LENGTH, Fq>::new(&input_str),
            vec![],
        )
        .unwrap();
        r.assert_satisfied();
    }

    #[test]
    fn valid_2() {
        let input_str = ['(', ZERO_CHAR, ')'];
        let r = MockProver::run(
            K,
            &BracketCircuit::<MAX_LENGTH, Fq>::new(&input_str),
            vec![],
        )
        .unwrap();
        r.assert_satisfied();
    }

    #[test]
    fn valid_3() {
        let input_str = [ZERO_CHAR, ZERO_CHAR, '(', ZERO_CHAR, ')', ZERO_CHAR];
        let r = MockProver::run(
            K,
            &BracketCircuit::<MAX_LENGTH, Fq>::new(&input_str),
            vec![],
        )
        .unwrap();
        r.assert_satisfied();
    }

    #[test]
    fn valid_all_zero() {
        let input_str = [ZERO_CHAR, ZERO_CHAR, ZERO_CHAR];
        let r = MockProver::run(
            K,
            &BracketCircuit::<MAX_LENGTH, Fq>::new(&input_str),
            vec![],
        )
        .unwrap();
        r.assert_satisfied();
    }

    #[test]
    #[should_panic]
    fn unvalid_string_length() {
        const MAX_LENGTH: usize = 3;
        let input_str = ['(', ZERO_CHAR, ZERO_CHAR, ZERO_CHAR, ')'];
        MockProver::run(
            K,
            &BracketCircuit::<MAX_LENGTH, Fq>::new(&input_str),
            vec![],
        )
        .unwrap();
    }

    #[test]
    fn unvalid_order() {
        let input_str = [')', '('];
        MockProver::run(
            K,
            &BracketCircuit::<MAX_LENGTH, Fq>::new(&input_str),
            vec![],
        )
        .unwrap()
        .verify()
        .unwrap_err();
    }
}

fn main() {}
