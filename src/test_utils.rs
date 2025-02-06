use alloy_primitives::B256;
use itertools::Itertools;
use snark_verifier_sdk::{
    evm::gen_evm_proof_shplonk,
    gen_pk,
    halo2::aggregation::AggregationCircuit,
    snark_verifier::halo2_base::{
        gates::circuit::{builder::BaseCircuitBuilder, BaseCircuitParams},
        halo2_proofs::{halo2curves::bn256::G1Affine, plonk::VerifyingKey},
        utils::fs::read_params,
    },
    CircuitExt,
};

use crate::{b256_to_fr, vkey::OnchainVerifyingKey};

/// The public values do not includes the first 384 bytes for KZG accumulator.
/// The public values must be in HiLo form because each B256 must fit into 254
/// bits.
///
/// Returns `(onchain_vk, proof, public_values)`.
/// For now we just prefix public values with 384=32*12 bytes of zeros. For a
/// better test this should use a real KZG accumulator and the circuit should be
/// an aggregation circuit.
pub fn generate_dummy_circuit(
    k: u32,
    public_values: &[B256],
) -> (VerifyingKey<G1Affine>, Vec<u8>, Vec<u8>, Vec<B256>) {
    let lookup_bits = k as usize - 1;
    let circuit_params = BaseCircuitParams {
        k: k as usize,
        num_advice_per_phase: vec![1],
        num_lookup_advice_per_phase: vec![1],
        num_fixed: 1,
        lookup_bits: Some(lookup_bits),
        num_instance_columns: 1,
    };
    let mut builder = BaseCircuitBuilder::new(false).use_params(circuit_params.clone());
    let mut instances = vec![];
    instances.resize(
        AggregationCircuit::accumulator_indices().unwrap().len(),
        B256::ZERO,
    );
    instances.extend(public_values.to_vec());
    let instances_fr = instances
        .iter()
        .map(|x| b256_to_fr(*x).unwrap())
        .collect_vec();
    let ctx = builder.main(0);
    let instances_assigned = ctx.assign_witnesses(instances_fr.clone());
    builder.assigned_instances[0] = instances_assigned;

    // NOTE: this requires the fixed trusted setup Axiom uses for the proof to
    // verify
    let params = read_params(k);
    // do not call calculate_params, we want to use fixed params
    let pk = gen_pk(&params, &builder, None);
    // use is_aggregation=true for signature prover
    let onchain_vk = OnchainVerifyingKey::from_vk(pk.get_vk(), instances.len(), false).unwrap();
    let proof = gen_evm_proof_shplonk(&params, &pk, builder, vec![instances_fr]);
    let onchain_vk_bytes = onchain_vk.write().unwrap();
    (pk.get_vk().clone(), onchain_vk_bytes, proof, instances)
}
