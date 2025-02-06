use std::io::Read;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use eyre::bail;
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::{
    halo2::aggregation::AggregationCircuit,
    snark_verifier::{
        halo2_base::{
            gates::circuit::BaseCircuitParams,
            halo2_proofs::{halo2curves::bn256::G1Affine, plonk::VerifyingKey},
        },
        system::halo2::{compile, Config},
        verifier::plonk::PlonkProtocol,
    },
    CircuitExt,
};

use crate::FAKE_KZG_PARAMS;

/// This metadata is only for a circuit built using `RlcCircuitBuilder`
/// or `BaseCircuitBuilder`, where the circuit _may_ be an aggregation circuit.
#[derive(Clone, Debug, Default, Serialize, Deserialize, Hash)]
#[serde(rename_all = "camelCase")]
pub struct OnchainCircuitMetadata {
    /// Version byte for domain separation on version of
    /// halo2-lib, snark-verifier (for example if we switch to mv_lookup).
    pub version: u8,
    /// Number of instances in each instance polynomial
    pub num_instance: Vec<u32>,
    /// Number of challenges to squeeze from transcript after each phase.
    /// This `num_challenge` counts only the challenges used inside the circuit
    /// - it excludes challenges that are part of the halo2 system. The full
    ///   challenges, which is what `plonk_protocol.num_challenge` stores, is:
    /// ```ignore
    /// [
    ///   my_phase0_challenges,
    ///   ...
    ///   [..my_phasen_challenges, theta],
    ///   [beta, gamma],
    ///   [alpha],
    /// ]
    /// ```
    pub num_challenge: Vec<u8>,

    /// Boolean for whether this is an Aggregation Circuit which has a KZG
    /// accumulator in the public instances. If true, it must be the first 12
    /// instances.
    pub is_aggregation: bool,

    // RlcCircuitParams:
    /// The number of advice columns per phase
    pub num_advice_per_phase: Vec<u16>,
    /// The number of special advice columns that have range lookup enabled per
    /// phase
    pub num_lookup_advice_per_phase: Vec<u8>,
    /// Number of advice columns for the RLC custom gate
    pub num_rlc_columns: u16,
    /// The number of fixed columns **only** for constants
    pub num_fixed: u8,
}

pub fn convert_vk_to_protocol(
    vk: &VerifyingKey<G1Affine>,
    num_public_values: usize,
    is_aggregation: bool,
) -> PlonkProtocol<G1Affine> {
    let acc_indices = if is_aggregation {
        AggregationCircuit::accumulator_indices()
    } else {
        None
    };
    // HACK to avoid needing kzg_params
    let k = vk.get_domain().k();
    let fake_params = FAKE_KZG_PARAMS.from_parts(
        k,
        vec![Default::default()],
        Some(vec![Default::default()]),
        Default::default(),
        Default::default(),
    );

    compile(
        &fake_params,
        vk,
        Config::kzg()
            .with_num_instance(vec![num_public_values])
            .with_accumulator_indices(acc_indices),
    )
}

/// Need to provide BaseCircuitParams for additional context, otherwise you have
/// to parse the BaseCircuitParams data from the custom gate information in
/// `protocol`
pub fn get_metadata_from_protocol(
    protocol: &PlonkProtocol<G1Affine>,
    params: BaseCircuitParams,
) -> eyre::Result<OnchainCircuitMetadata> {
    let num_advice_per_phase = params
        .num_advice_per_phase
        .iter()
        .map(|x| *x as u16)
        .collect();
    let num_lookup_advice_per_phase = params
        .num_lookup_advice_per_phase
        .iter()
        .map(|x| *x as u8)
        .collect();
    let num_rlc_columns = 0;
    let num_fixed = params.num_fixed as u8;
    let mut metadata = OnchainCircuitMetadata {
        version: 1,
        num_advice_per_phase,
        num_lookup_advice_per_phase,
        num_rlc_columns,
        num_fixed,
        ..Default::default()
    };

    if protocol.num_instance.len() != 1 {
        bail!("Only one instance column supported right now");
    }
    metadata.num_instance = protocol.num_instance.iter().map(|&x| x as u32).collect();
    let mut num_challenge_incl_system = protocol.num_challenge.clone();
    // This `num_challenge` counts only the challenges used inside the circuit - it
    // excludes challenges that are part of the halo2 system.
    // The full challenges, which is what `plonk_protocol.num_challenge` stores, is:
    // ```ignore
    // [
    //   my_phase0_challenges,
    //   ...
    //   [..my_phasen_challenges, theta],
    //   [beta, gamma],
    //   [alpha],
    // ]
    // ```
    if num_challenge_incl_system.pop() != Some(1) {
        bail!("last challenge must be [alpha]");
    }
    if num_challenge_incl_system.pop() != Some(2) {
        bail!("second last challenge must be [beta, gamma]");
    }
    let last_challenge = num_challenge_incl_system.last_mut();
    if last_challenge.is_none() {
        bail!("num_challenge must have at least 3 challenges");
    }
    let last_challenge = last_challenge.unwrap();
    if *last_challenge == 0 {
        bail!("third last challenge must include theta");
    }
    *last_challenge -= 1;
    let num_challenge: Vec<u8> = num_challenge_incl_system.iter().map(|x| *x as u8).collect();
    if num_challenge != vec![0] && num_challenge != vec![1, 0] {
        bail!("Only phase0 BaseCircuitBuilder or phase0+1 RlcCircuitBuilder supported right now");
    }
    metadata.num_challenge = num_challenge;

    metadata.is_aggregation = if protocol.accumulator_indices.is_empty() {
        false
    } else {
        if protocol.accumulator_indices.len() != 1
            || protocol.accumulator_indices[0] != AggregationCircuit::accumulator_indices().unwrap()
        {
            bail!("invalid accumulator indices");
        }
        true
    };

    Ok(metadata)
}

impl OnchainCircuitMetadata {
    pub fn encode(&self) -> eyre::Result<[u8; 32]> {
        let mut encoded = vec![];
        encoded.write_u8(self.version)?;

        encoded.write_u8(self.num_instance.len().try_into()?)?;
        for &num_instance in &self.num_instance {
            encoded.write_u32::<BigEndian>(num_instance)?;
        }

        let num_phase = self.num_challenge.len();
        if num_phase == 0 {
            bail!("num_challenge must be non-empty")
        }
        encoded.write_u8(num_phase.try_into()?)?;
        for &num_challenge in &self.num_challenge {
            encoded.write_u8(num_challenge)?;
        }

        encoded.write_u8(self.is_aggregation as u8)?;

        // encode RlcCircuitParams:
        if self.num_advice_per_phase.len() > num_phase {
            bail!("num_advice_per_phase must be <= num_phase")
        }
        let mut num_advice_cols = self.num_advice_per_phase.clone();
        num_advice_cols.resize(num_phase, 0);
        for num_advice_col in num_advice_cols {
            encoded.write_u16::<BigEndian>(num_advice_col)?;
        }

        if self.num_lookup_advice_per_phase.len() > num_phase {
            bail!("num_lookup_advice_per_phase must be <= num_phase")
        }
        let mut num_lookup_advice_cols = self.num_lookup_advice_per_phase.clone();
        num_lookup_advice_cols.resize(num_phase, 0);
        for num_lookup_advice_col in num_lookup_advice_cols {
            encoded.write_u8(num_lookup_advice_col)?;
        }

        encoded.write_u16::<BigEndian>(self.num_rlc_columns)?;
        encoded.write_u8(self.num_fixed)?;

        if encoded.len() > 32 {
            bail!("circuit metadata cannot be packed into bytes32")
        }
        encoded.resize(32, 0);
        Ok(encoded.try_into().unwrap())
    }

    /// Doesn't enforce that reader reads exactly 32 bytes, it may be less
    pub fn decode(mut reader: impl Read) -> eyre::Result<Self> {
        let version = reader.read_u8()?;

        // Read num_instance
        let num_instance_len = reader.read_u8()? as usize;
        let mut num_instance = Vec::with_capacity(num_instance_len);
        for _ in 0..num_instance_len {
            num_instance.push(reader.read_u32::<BigEndian>()?);
        }

        // Read num_challenge
        let num_phase = reader.read_u8()? as usize;
        if num_phase == 0 {
            bail!("num_challenge must be non-empty");
        }
        let mut num_challenge = Vec::with_capacity(num_phase);
        for _ in 0..num_phase {
            num_challenge.push(reader.read_u8()?);
        }

        // Read is_aggregation
        let is_aggregation = reader.read_u8()? != 0;

        // Read num_advice_per_phase
        let mut num_advice_per_phase = Vec::with_capacity(num_phase);
        for _ in 0..num_phase {
            num_advice_per_phase.push(reader.read_u16::<BigEndian>()?);
        }
        // Read num_lookup_advice_per_phase
        let mut num_lookup_advice_per_phase = Vec::with_capacity(num_phase);
        for _ in 0..num_phase {
            num_lookup_advice_per_phase.push(reader.read_u8()?);
        }
        // Read num_rlc_columns and num_fixed
        let num_rlc_columns = reader.read_u16::<BigEndian>()?;
        let num_fixed = reader.read_u8()?;

        Ok(OnchainCircuitMetadata {
            version,
            num_instance,
            num_challenge,
            is_aggregation,
            num_advice_per_phase,
            num_lookup_advice_per_phase,
            num_rlc_columns,
            num_fixed,
        })
    }
}
