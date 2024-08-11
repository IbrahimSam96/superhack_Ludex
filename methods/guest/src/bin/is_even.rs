use alloy_primitives::U256;
use alloy_sol_types::SolValue;
use risc0_zkvm::guest::env;
use std::io::Read;

fn main() {
    // Read the input data for this application.
    let mut input_bytes = Vec::<u8>::new();
    env::stdin().read_to_end(&mut input_bytes).unwrap();

    // Decode and parse the input hash
    let input_hash = <U256>::abi_decode(&input_bytes, true).unwrap();

    // Define the predefined hashed password (replace with your actual hashed password)
    let predefined_number = U256::from(12345);

    assert!(input_hash == predefined_number);

    env::commit_slice(input_hash.abi_encode().as_slice());
}
