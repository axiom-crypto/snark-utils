use std::{
    io::{Read, Write},
    marker::PhantomData,
};

use byteorder::{ReadBytesExt, WriteBytesExt};
use eyre::Context;
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::{
    halo2::aggregation::AggregationCircuit,
    snark_verifier::{
        halo2_base::{
            gates::circuit::{BaseCircuitParams, BaseConfig},
            halo2_proofs::{
                circuit::{Layouter, SimpleFloorPlanner},
                halo2curves::bn256::{Bn256, Fr, G1Affine},
                plonk::{self, keygen_vk_custom, Circuit, ConstraintSystem, VerifyingKey},
                poly::kzg::commitment::ParamsKZG,
            },
            utils::ScalarField,
        },
        system::halo2::{compile, transcript_initial_state, Config},
        util::arithmetic::{root_of_unity, CurveAffine, Domain, GroupEncoding, PrimeField},
        verifier::plonk::PlonkProtocol,
    },
    CircuitExt,
};

use crate::{
    metadata::{convert_vk_to_protocol, get_metadata_from_protocol, OnchainCircuitMetadata},
    utils::{read_curve_compressed, read_field_le, write_curve_compressed, write_field_le},
};

#[derive(Clone, Debug, Serialize, Deserialize, Hash)]
pub struct OnchainVerifyingKey<C: CurveAffine> {
    pub circuit_metadata: OnchainCircuitMetadata,
    pub transcript_initial_state: C::Scalar,
    pub preprocessed: Vec<C>,
    /// The circuit is going to be of a fixed matrix height (number of rows).
    /// This `k` is the log2 height.
    pub k: u8,
}

impl OnchainVerifyingKey<G1Affine> {
    // @dev Remark: PlonkProtocol fields are public so we can perform "surgery" on
    // them, whereas halo2 VerifyingKey has all fields private so we can't.
    pub fn into_plonk_protocol(self) -> eyre::Result<PlonkProtocol<G1Affine>> {
        let OnchainVerifyingKey {
            circuit_metadata,
            transcript_initial_state,
            preprocessed,
            k,
        } = self;
        // We can make a dummy trusted setup here because we replace the fixed
        // commitments afterwards
        let kzg_params = ParamsKZG::<Bn256>::setup(DUMMY_K, StdRng::seed_from_u64(0));
        let dummy_vk = dummy_vk_from_metadata(&kzg_params, circuit_metadata.clone())?;
        let num_instance = circuit_metadata
            .num_instance
            .iter()
            .map(|x| *x as usize)
            .collect();
        let acc_indices = circuit_metadata
            .is_aggregation
            .then(|| AggregationCircuit::accumulator_indices().unwrap());
        let mut protocol = compile(
            &kzg_params,
            &dummy_vk,
            Config::kzg()
                .with_num_instance(num_instance)
                .with_accumulator_indices(acc_indices),
        );
        // See [snark_verifier::system::halo2::compile] to see how [PlonkProtocol] is
        // constructed These are the parts of `protocol` that are different for
        // different vkeys or different `k`
        let k = k as usize;
        protocol.domain = Domain::new(k, root_of_unity(k));
        protocol.domain_as_witness = None;
        protocol.preprocessed = preprocessed;
        protocol.transcript_initial_state = Some(transcript_initial_state);
        // Do not MSM public instances (P::QUERY_INSTANCE should be false)
        protocol.instance_committing_key = None;
        protocol.linearization = None;
        Ok(protocol)
    }

    /// - `is_aggregation`: if `vk` is the vk for aggregation circuit
    /// - **assumes** circuit is halo2-base with 1 advice column, lookup enabled
    pub fn from_vk(
        vk: &VerifyingKey<G1Affine>,
        num_public_values: usize,
        is_aggregation: bool,
    ) -> eyre::Result<Self> {
        let k = vk.get_domain().k() as usize;
        let circuit_params = BaseCircuitParams {
            k,
            num_advice_per_phase: vec![1],
            num_fixed: 1,
            num_lookup_advice_per_phase: vec![1],
            lookup_bits: Some(k - 1),
            num_instance_columns: 1,
        };
        let protocol = convert_vk_to_protocol(vk, num_public_values, is_aggregation);
        let metadata = get_metadata_from_protocol(&protocol, circuit_params)?;
        Ok(get_onchain_vk_from_vk(vk, metadata))
    }

    pub fn write(&self) -> eyre::Result<Vec<u8>> {
        let metadata = self.circuit_metadata.encode()?;

        let tmp = <G1Affine as GroupEncoding>::Repr::default();
        let compressed_curve_bytes = tmp.as_ref().len();
        let tmp = <Fr as PrimeField>::Repr::default();
        let field_bytes = tmp.as_ref().len();
        let mut writer =
            Vec::with_capacity(field_bytes + self.preprocessed.len() * compressed_curve_bytes);

        writer.write_all(&metadata)?;
        write_field_le(&mut writer, self.transcript_initial_state)?;
        writer.write_u8(self.preprocessed.len().try_into().unwrap())?;
        for &point in &self.preprocessed {
            write_curve_compressed(&mut writer, point)?;
        }
        writer.write_u8(self.k)?;
        Ok(writer)
    }

    pub fn read(mut reader: impl Read) -> eyre::Result<Self> {
        // Read metadata (32 bytes)
        let mut metadata_bytes = [0u8; 32];
        reader.read_exact(&mut metadata_bytes)?;
        let circuit_metadata = OnchainCircuitMetadata::decode(&mut &metadata_bytes[..])
            .context("decode circuit metadata")?;

        // Read transcript initial state
        let transcript_initial_state =
            read_field_le(&mut reader).context("read transcript initial state")?;

        // Read preprocessed points, there's no more bytes32 after this
        let num_preprocessed = reader.read_u8().context("read num preprocessed")? as usize;
        let mut preprocessed: Vec<G1Affine> = Vec::with_capacity(num_preprocessed);
        for _ in 0..num_preprocessed {
            let point = read_curve_compressed(&mut reader)?;
            preprocessed.push(point);
        }

        // Read k: u8
        let k = reader.read_u8().context("read k")?;

        Ok(OnchainVerifyingKey {
            circuit_metadata,
            transcript_initial_state,
            preprocessed,
            k,
        })
    }
}

/// Requires additional context about the Axiom circuit, in the form of the
/// `circuit_metadata`.
pub fn get_onchain_vk_from_vk<C: CurveAffine>(
    vk: &VerifyingKey<C>,
    circuit_metadata: OnchainCircuitMetadata,
) -> OnchainVerifyingKey<C> {
    let preprocessed = vk
        .fixed_commitments()
        .iter()
        .chain(vk.permutation().commitments().iter())
        .cloned()
        .map(Into::into)
        .collect();
    let transcript_initial_state = transcript_initial_state(vk);
    OnchainVerifyingKey {
        circuit_metadata,
        preprocessed,
        transcript_initial_state,
        k: vk.get_domain().k().try_into().unwrap(),
    }
}

pub fn get_onchain_vk_from_protocol<C: CurveAffine>(
    protocol: &PlonkProtocol<C>,
    circuit_metadata: OnchainCircuitMetadata,
) -> OnchainVerifyingKey<C> {
    let preprocessed = protocol.preprocessed.clone();
    let transcript_initial_state = protocol.transcript_initial_state.unwrap();
    OnchainVerifyingKey {
        circuit_metadata,
        preprocessed,
        transcript_initial_state,
        k: protocol.domain.k.try_into().unwrap(),
    }
}

/// We only care about evaluations (custom gates) but not the domain, so we use
/// a very small dummy
pub(super) const DUMMY_K: u32 = 7;

/// Dummy circuit just to get the correct constraint system corresponding
/// to the circuit metadata.
#[derive(Clone)]
struct DummyCircuit<F> {
    metadata: OnchainCircuitMetadata,
    _marker: PhantomData<F>,
}

// For internal use only
impl<F: ScalarField> Circuit<F> for DummyCircuit<F> {
    type Config = BaseConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = OnchainCircuitMetadata;

    fn without_witnesses(&self) -> Self {
        self.clone()
    }

    fn params(&self) -> Self::Params {
        self.metadata.clone()
    }

    fn configure_with_params(
        meta: &mut ConstraintSystem<F>,
        metadata: Self::Params,
    ) -> Self::Config {
        let num_phase = metadata.num_challenge.len();
        assert!(num_phase == 1, "only support 1 phases");
        let base_circuit_params = BaseCircuitParams {
            k: DUMMY_K as usize,
            num_advice_per_phase: metadata
                .num_advice_per_phase
                .iter()
                .map(|x| *x as usize)
                .collect(),
            num_fixed: metadata.num_fixed as usize,
            num_lookup_advice_per_phase: metadata
                .num_lookup_advice_per_phase
                .iter()
                .map(|x| *x as usize)
                .collect(),
            lookup_bits: Some(DUMMY_K as usize - 1), /* doesn't matter because we replace fixed
                                                      * commitments later */
            num_instance_columns: metadata.num_instance.len(),
        };
        assert!(metadata.num_rlc_columns == 0,);
        // Note that BaseConfig ignores lookup bits if there are no lookup advice
        // columns
        BaseConfig::configure(meta, base_circuit_params)
    }

    fn configure(_: &mut ConstraintSystem<F>) -> Self::Config {
        unreachable!("must use configure_with_params")
    }

    fn synthesize(
        &self,
        _config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), plonk::Error> {
        layouter.assign_region(|| "dummy", |_region| Ok(()))
    }
}

/// For internal use only, num_instance will be replaced later
pub(crate) fn dummy_vk_from_metadata(
    params: &ParamsKZG<Bn256>,
    metadata: OnchainCircuitMetadata,
) -> eyre::Result<VerifyingKey<G1Affine>> {
    let dummy_circuit = DummyCircuit::<Fr> {
        metadata,
        _marker: PhantomData,
    };
    let vk = keygen_vk_custom(params, &dummy_circuit, false)?;
    Ok(vk)
}
