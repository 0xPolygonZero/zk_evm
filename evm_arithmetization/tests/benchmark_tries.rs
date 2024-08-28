use ethereum_types::{H160, H256, U256};
use evm_arithmetization::generation::mpt::AccountRlp;
use evm_arithmetization::generation::{GenerationInputs, TrieInputs};
use evm_arithmetization::proof::TrieRoots;
use evm_arithmetization::prover::testing::simulate_execution;
use evm_arithmetization::testing_utils::{init_logger, insert_storage};
use evm_arithmetization::Node;
use keccak_hash::keccak;
use mpt_trie::nibbles::Nibbles;
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use plonky2::field::goldilocks_field::GoldilocksField;
use rand::{thread_rng, RngCore};

type F = GoldilocksField;

type StorageTrie = (H256, HashedPartialTrie);

fn rand_u256(rng: &mut impl RngCore) -> U256 {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    U256::from_big_endian(&bytes)
}

fn generate_state_trie(
    num_accounts: usize,
    num_slots_per_account: usize,
) -> anyhow::Result<(HashedPartialTrie, Vec<StorageTrie>)> {
    let mut rng = thread_rng();

    let mut state_trie = HashedPartialTrie::from(Node::Empty);
    let mut storage_tries = vec![];
    for _ in 0..num_accounts {
        let mut storage_trie = Node::Empty.into();
        for _ in 0..num_slots_per_account {
            insert_storage(&mut storage_trie, rand_u256(&mut rng), rand_u256(&mut rng))?;
        }
        let address = H160::random();
        let state_key = keccak(address);
        let nibbles = Nibbles::from_bytes_be(state_key.as_bytes()).unwrap();

        let account = AccountRlp {
            storage_root: storage_trie.hash(),
            ..Default::default()
        };

        storage_tries.push((state_key, storage_trie));

        state_trie.insert(nibbles, rlp::encode(&account).to_vec())?;
    }

    Ok((state_trie, storage_tries))
}

fn generate_inputs(
    num_accounts: usize,
    num_slots_per_account: usize,
) -> anyhow::Result<GenerationInputs> {
    let (state_trie, storage_tries) = generate_state_trie(num_accounts, num_slots_per_account)?;

    let trie_roots_after = TrieRoots {
        state_root: state_trie.hash(),
        transactions_root: HashedPartialTrie::from(Node::Empty).hash(),
        receipts_root: HashedPartialTrie::from(Node::Empty).hash(),
    };

    let tries_before = TrieInputs {
        state_trie,
        transactions_trie: HashedPartialTrie::from(Node::Empty),
        receipts_trie: HashedPartialTrie::from(Node::Empty),
        storage_tries,
    };

    let inputs = GenerationInputs {
        tries: tries_before,
        trie_roots_after,
        txn_number_before: 1.into(), // to skip beacon roots update
        ..Default::default()
    };

    Ok(inputs)
}

/// Test a simple token transfer to a new address.
#[test]
fn test_simple_transfer() -> anyhow::Result<()> {
    init_logger();

    for num_accounts in [0_usize, 1, 2, 10, 100].into_iter() {
        for num_slots_per_account in [0_usize, 1, 2, 10, 100].into_iter() {
            let inputs = generate_inputs(num_accounts, num_slots_per_account)?;
            println!(
                "\n{:?} accounts with {:?} non-zero slots each",
                num_accounts, num_slots_per_account
            );
            println!(
                "State trie size: {:?} bytes",
                serde_json::to_vec(&inputs.tries.state_trie).unwrap().len()
            );
            simulate_execution::<F>(inputs)?;
        }
        println!("\n=============================\n");
    }

    Ok(())
}
