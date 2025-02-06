use alloy_primitives::B256;
use eyre::eyre;
use metadata::convert_vk_to_protocol;
use snark_verifier_sdk::{
    snark_verifier::{
        halo2_base::halo2_proofs::{
            halo2curves::bn256::{Bn256, Fr, G1Affine},
            plonk::VerifyingKey,
            poly::{
                commitment::CommitmentScheme,
                kzg::commitment::{KZGCommitmentScheme, ParamsKZG},
            },
        },
        pcs::kzg::KzgDecidingKey,
        system::halo2::transcript::evm::EvmTranscript,
        util::arithmetic::PrimeField,
        verifier::{
            plonk::{PlonkProof, PlonkProtocol},
            SnarkVerifier,
        },
    },
    NativeLoader, PlonkVerifier, SHPLONK,
};
use vkey::OnchainVerifyingKey;

// Mostly copied from axiom-query/src/utils/client_circuit
pub mod metadata;
pub(crate) mod utils;
pub mod vkey;

lazy_static::lazy_static! {
    /// This is just the generator of the curve. It should never change.
    pub static ref SVK: G1Affine =
        serde_json::from_str("\"0100000000000000000000000000000000000000000000000000000000000000\"")
            .unwrap();

    /// This commits to the trusted setup used to generate all proving keys.
    /// This MUST be updated whenever the trusted setup is changed.
    pub static ref DK: KzgDecidingKey<Bn256> = serde_json::from_str(r#"
          {
            "_marker": null,
            "g2": "edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19",
            "s_g2": "0016e2a0605f771222637bae45148c8faebb4598ee98f30f20f790a0c3c8e02a7bf78bf67c4aac19dcc690b9ca0abef445d9a576c92ad6041e6ef1413ca92a17",
            "svk": {
              "g": "0100000000000000000000000000000000000000000000000000000000000000"
            }
          }
       "#).unwrap();
}

// TODO[jpw]: ideally we should use thiserror instead of eyre
pub fn verify_axiom_proof(
    onchain_vk: OnchainVerifyingKey<G1Affine>,
    proof: &[u8],
    public_values: &[B256],
) -> eyre::Result<()> {
    let dk = &DK;
    let protocol = onchain_vk.into_plonk_protocol()?;
    native_verify_evm_proof(dk, &protocol, proof, public_values)
}

lazy_static::lazy_static! {
    static ref FAKE_KZG_PARAMS: ParamsKZG<Bn256> = KZGCommitmentScheme::new_params(1);
}

/// - `is_aggregation`: if the `proof` is an aggregation proof
pub fn native_verify_evm_proof_vk(
    vk: &VerifyingKey<G1Affine>,
    proof: &[u8],
    public_values: &[B256],
    is_aggregation: bool,
) -> eyre::Result<()> {
    let protocol = convert_vk_to_protocol(vk, public_values.len(), is_aggregation);
    native_verify_evm_proof(&DK, &protocol, proof, public_values)
}

/// Native (in rust) verification of EVM proof, including the KZG accumulator.
/// This verifies snark with transcript using **keccak** and importantly also
/// checks the kzg accumulator from the public instances, if `protocol`
/// specifies the proof is for an aggregation circuit
pub fn native_verify_evm_proof(
    dk: &KzgDecidingKey<Bn256>,
    protocol: &PlonkProtocol<G1Affine>,
    proof: &[u8],
    public_values: &[B256],
) -> eyre::Result<()> {
    let instances = public_values
        .iter()
        .map(|x| b256_to_fr(*x))
        .collect::<Result<Vec<_>, _>>()?;
    let mut transcript = EvmTranscript::<_, NativeLoader, _, _>::new(proof);
    let proof: PlonkProof<_, _, SHPLONK> =
        PlonkVerifier::read_proof(dk, protocol, &[instances.clone()], &mut transcript)
            .map_err(|e| eyre!("Failed to read PlonkProof: {e:?}"))?;
    PlonkVerifier::verify(dk, protocol, &[instances], &proof)
        .map_err(|e| eyre!("PlonkVerifier failed: {e:?}"))?;
    Ok(())
}

pub fn b256_to_fr(bytes_be: B256) -> eyre::Result<Fr> {
    let mut buf = bytes_be.0;
    buf.reverse();
    Fr::from_repr(buf)
        .into_option()
        .ok_or(eyre!("invalid Fr point encoding"))
}

#[cfg(feature = "test-utils")]
pub mod test_utils;
