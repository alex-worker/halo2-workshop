use std::marker::PhantomData;
use halo2_proofs::{
    circuit::{Region, Layouter, SimpleFloorPlanner, Value},
    pasta::group::ff::PrimeField,
    plonk::{self, Advice, Circuit, Column, ConstraintSystem, Expression, Selector, TableColumn},
    poly::Rotation,
};
use halo2_proofs::circuit::AssignedCell;

// Stores the configuration of the table (columns) that the circuit needs
#[derive(Clone)]
pub struct BracketConfig {
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

struct BracketChip<F: PrimeField> {
    config: BracketConfig,
    _p: PhantomData<F>,
}

impl<F: PrimeField> BracketChip<F> {
    pub fn construct(config: BracketConfig) -> Self {
        Self {
            config,
            _p: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> BracketConfig {

        let config = BracketConfig {
            s_input: meta.selector(),
            s_is_accum_zero: meta.selector(),
            s_not_minus_one: meta.selector(),
            input: meta.advice_column(),
            accum: meta.advice_column(),
            inverted_accum_plus_1: meta.advice_column(),
            allowed: meta.lookup_table_column(),
        };

        // f(x) = 81 - 2*input
        meta.create_gate("accumulation", |meta| {
            let _81 = Expression::Constant(F::from(81));
            let _2 = Expression::Constant(F::from(2));

            let s_input = meta.query_selector(config.s_input);
            let s_is_accum_zero = meta.query_selector(config.s_is_accum_zero);
            // let s_not_minus_one = meta.query_selector(config.s_not_minus_one);

            let input = meta.query_advice(config.input, Rotation::cur());
            let prev = meta.query_advice(config.accum, Rotation::cur());
            let result = meta.query_advice(config.accum, Rotation::next());

            vec![
                s_input * (prev.clone() + (_81 - _2 * input) - result),
                s_is_accum_zero * prev
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

    pub fn assign_table_allowed(&self, mut layouter: impl Layouter<F>,) {
        layouter.assign_table(
            || "allowed",
            |mut table| {
                table.assign_cell(|| "empty", self.config.allowed, 0, || Value::known(F::ZERO))?;
                table.assign_cell(
                    || "(",
                    self.config.allowed,
                    1,
                    || Value::known(F::from('(' as u64)),
                )?;
                table.assign_cell(
                    || ")",
                    self.config.allowed,
                    2,
                    || Value::known(F::from(')' as u64)),
                )?;

                Ok(())
            },
        ).unwrap();
    }

    pub fn assign_accum(&self, region: &mut Region<F>, offset: usize, value: Value<F>) -> Result<AssignedCell<F, F>, plonk::Error>{
        let accum = region.assign_advice(|| "accum", self.config.accum, offset, || value)?;
        Ok(accum)
    }

    pub fn assign_input(&self, region: &mut Region<F>, offset: usize, value: Value<F>) -> Result<AssignedCell<F, F>, plonk::Error>{
        let assign_input = region.assign_advice(|| "input", self.config.input, offset, || value)?;
        Ok(assign_input)
    }

    pub fn assign_inverted_accum_plus_1(&self, region: &mut Region<F>, accum: Value<F>, offset: usize) -> Result<AssignedCell<F, F>, plonk::Error> {
        let value = accum.map(|val| val.add(F::ONE).invert().unwrap_or_else(|| F::ZERO));
        let inv = region.assign_advice(
            || "inverted accum",
            self.config.inverted_accum_plus_1,
            offset,
            || value
        )?;
        Ok(inv)
    }
}

// Sets the circuit, and also stores the private input
pub struct BracketCircuit<const L: usize, F: PrimeField> {
    char_input: [char; L],
    _p: PhantomData<F>,
}

impl<const L: usize, F: PrimeField> BracketCircuit<L, F> {
    pub fn new(input: [char; L]) -> Self {
        Self {
            char_input: input,
            _p: PhantomData,
        }
    }
}

impl<const L: usize, F: PrimeField> Circuit<F> for BracketCircuit<L, F> {
    type Config = BracketConfig;

    // Not important at this stage
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        todo!("Not needed at this stage.")
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        BracketChip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), plonk::Error> {
        let chip = BracketChip::construct(config.clone());

        chip.assign_table_allowed(layouter.namespace(|| "assign_table_allowed row"));

        layouter.assign_region(
            || "",
            |mut region| {
                let _81 = Value::known(F::from(81));
                let _2 = Value::known(F::from(2));

                let prev = chip.assign_accum(&mut region, 0, Value::known(F::ZERO))?;
                chip.assign_inverted_accum_plus_1(&mut region, prev.value().copied(), 0)?;

                config.s_not_minus_one.enable(&mut region, 0)?;
                // config.s_is_accum_zero.enable(&mut region, L)?;

                self.char_input
                    .iter()
                    .map(|sym| Value::known(F::from(*sym as u64)))
                    .enumerate()
                    .try_fold(prev.value().copied(), |prev, (offset, sym)| {
                        config.s_input.enable(&mut region, offset)?;
                        config.s_not_minus_one.enable(&mut region, offset + 1)?;

                        chip.assign_input(&mut region, offset, sym)?;

                        let acc_value = _81 - (_2 * sym) + prev;

                        chip.assign_accum(&mut region, offset + 1, acc_value)?;
                        chip.assign_inverted_accum_plus_1(&mut region, acc_value, offset+1)?;

                        Result::<_, plonk::Error>::Ok(acc_value)
                    })?;

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

    #[test]
    fn unvalid_sym() {
        MockProver::run(K, &BracketCircuit::<1, Fq>::new(['*']), vec![])
            .unwrap()
            .verify()
            .unwrap_err();
    }

    #[test]
    fn valid_1() {
        MockProver::run(K, &BracketCircuit::<2, Fq>::new(['(', ')']), vec![])
            .unwrap()
            .verify()
            .unwrap();
    }

    #[test]
    fn unvalid_order() {
        MockProver::run(K, &BracketCircuit::<2, Fq>::new([')', '(']), vec![])
            .unwrap()
            .verify()
            .unwrap_err();
    }

    // #[cfg(feature = "dev-graph")]
    #[test]
    fn plot_fibonacci1() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("fib-1-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("Fib 1 Layout", ("sans-serif", 60)).unwrap();

        let circuit = BracketCircuit::<2, Fq>::new([')', '(']);
        halo2_proofs::dev::CircuitLayout::default()
          .render(4, &circuit, &root)
          .unwrap();

        // let prover = MockProver::run(10, &BracketCircuit::<1, Fq>::new(['*']), vec![]).unwrap();
        // halo2_proofs::dev::
    }
}
