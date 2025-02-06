use std::fs::File;

use alloy_primitives::B256;
use snark_utils::{
    native_verify_evm_proof_vk, test_utils::generate_dummy_circuit, verify_axiom_proof,
    vkey::OnchainVerifyingKey,
};

fn main() {
    let pvs = [0, 1, 2, 3].map(|x| {
        let mut buf = B256::ZERO;
        *buf.0.last_mut().unwrap() = x;
        buf
    });
    let (vk, onchain_vk_bytes, proof, public_values) = generate_dummy_circuit(9, &pvs);

    // non-mock proofs will need is_aggregation=true
    native_verify_evm_proof_vk(&vk, &proof, &public_values, false).unwrap();
    // what node should use:
    let reader = &mut &onchain_vk_bytes[..]; // a mutable pointer to a slice(pointer) implements Read
    let onchain_vk = OnchainVerifyingKey::read(reader).unwrap();
    verify_axiom_proof(onchain_vk.clone(), &proof, &public_values).unwrap();

    // serializing in json to be deserialized for testing purposes
    serde_json::to_writer(
        File::create("magic.json").unwrap(),
        &(onchain_vk, proof, public_values),
    )
    .unwrap();
}
