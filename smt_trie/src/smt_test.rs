use ethereum_types::U256;
use plonky2::field::types::{Field, Sample};
use plonky2::hash::hash_types::HashOut;
use rand::seq::SliceRandom;
use rand::{random, thread_rng, Rng};

use crate::bits::Bits;
use crate::db::Db;
use crate::smt::HASH_TYPE;
use crate::utils::hashout2u;
use crate::{
    db::MemoryDb,
    smt::{hash_serialize, Key, Smt, F},
};

#[test]
fn test_add_and_rem() {
    let mut smt = Smt::<MemoryDb>::default();

    let k = Key(F::rand_array());
    let v = U256(thread_rng().gen());
    smt.set(k, v);
    assert_eq!(v, smt.get(k));

    smt.set(k, U256::zero());
    assert_eq!(smt.root.elements, [F::ZERO; 4]);

    let ser = smt.to_vec();
    assert_eq!(hash_serialize(&ser), smt.root);
}

#[test]
fn test_add_and_rem_hermez() {
    let mut smt = Smt::<MemoryDb>::default();

    let k = Key([F::ONE, F::ZERO, F::ZERO, F::ZERO]);
    let v = U256::from(2);
    smt.set(k, v);
    assert_eq!(v, smt.get(k));
    assert_eq!(
        smt.root.elements,
        [
            16483217357039062949,
            6830539605347455377,
            6826288191577443203,
            8219762152026661456
        ]
        .map(F::from_canonical_u64)
    );

    smt.set(k, U256::zero());
    assert_eq!(smt.root.elements, [F::ZERO; 4]);

    let ser = smt.to_vec();
    assert_eq!(hash_serialize(&ser), smt.root);
}

#[test]
fn test_update_element_1() {
    let mut smt = Smt::<MemoryDb>::default();

    let k = Key(F::rand_array());
    let v1 = U256(thread_rng().gen());
    let v2 = U256(thread_rng().gen());
    smt.set(k, v1);
    let root = smt.root;
    smt.set(k, v2);
    smt.set(k, v1);
    assert_eq!(smt.root, root);

    let ser = smt.to_vec();
    assert_eq!(hash_serialize(&ser), smt.root);
}

#[test]
fn test_add_shared_element_2() {
    let mut smt = Smt::<MemoryDb>::default();

    let k1 = Key(F::rand_array());
    let k2 = Key(F::rand_array());
    assert_ne!(k1, k2, "Unlucky");
    let v1 = U256(thread_rng().gen());
    let v2 = U256(thread_rng().gen());
    smt.set(k1, v1);
    smt.set(k2, v2);
    smt.set(k1, U256::zero());
    smt.set(k2, U256::zero());
    assert_eq!(smt.root.elements, [F::ZERO; 4]);

    let ser = smt.to_vec();
    assert_eq!(hash_serialize(&ser), smt.root);
}

#[test]
fn test_add_shared_element_3() {
    let mut smt = Smt::<MemoryDb>::default();

    let k1 = Key(F::rand_array());
    let k2 = Key(F::rand_array());
    let k3 = Key(F::rand_array());
    let v1 = U256(thread_rng().gen());
    let v2 = U256(thread_rng().gen());
    let v3 = U256(thread_rng().gen());
    smt.set(k1, v1);
    smt.set(k2, v2);
    smt.set(k3, v3);
    smt.set(k1, U256::zero());
    smt.set(k2, U256::zero());
    smt.set(k3, U256::zero());
    assert_eq!(smt.root.elements, [F::ZERO; 4]);

    let ser = smt.to_vec();
    assert_eq!(hash_serialize(&ser), smt.root);
}

#[test]
fn test_add_remove_128() {
    let mut smt = Smt::<MemoryDb>::default();

    let kvs = (0..128)
        .map(|_| {
            let k = Key(F::rand_array());
            let v = U256(thread_rng().gen());
            smt.set(k, v);
            (k, v)
        })
        .collect::<Vec<_>>();
    for &(k, v) in &kvs {
        smt.set(k, v);
    }
    for &(k, _) in &kvs {
        smt.set(k, U256::zero());
    }
    assert_eq!(smt.root.elements, [F::ZERO; 4]);

    let ser = smt.to_vec();
    assert_eq!(hash_serialize(&ser), smt.root);
}

#[test]
fn test_should_read_random() {
    let mut smt = Smt::<MemoryDb>::default();

    let kvs = (0..128)
        .map(|_| {
            let k = Key(F::rand_array());
            let v = U256(thread_rng().gen());
            smt.set(k, v);
            (k, v)
        })
        .collect::<Vec<_>>();
    for &(k, v) in &kvs {
        smt.set(k, v);
    }
    for &(k, v) in &kvs {
        assert_eq!(smt.get(k), v);
    }

    let ser = smt.to_vec();
    assert_eq!(hash_serialize(&ser), smt.root);
}

#[test]
fn test_add_element_similar_key() {
    let mut smt = Smt::<MemoryDb>::default();

    let k1 = Key([F::ZERO; 4]);
    let k2 = Key([F::from_canonical_u16(15), F::ZERO, F::ZERO, F::ZERO]);
    let k3 = Key([F::from_canonical_u16(31), F::ZERO, F::ZERO, F::ZERO]);
    let v1 = U256::from(2);
    let v2 = U256::from(3);
    smt.set(k1, v1);
    smt.set(k2, v1);
    smt.set(k3, v2);

    let expected_root = [
        442750481621001142,
        12174547650106208885,
        10730437371575329832,
        4693848817100050981,
    ]
    .map(F::from_canonical_u64);
    assert_eq!(smt.root.elements, expected_root);

    let ser = smt.to_vec();
    assert_eq!(hash_serialize(&ser), smt.root);
}

#[test]
fn test_leaf_one_level_depth() {
    let mut smt = Smt::<MemoryDb>::default();

    let k0 = Key([
        15508201873038097485,
        13226964191399612151,
        16289586894263066011,
        5039894867879804772,
    ]
    .map(F::from_canonical_u64));
    let k1 = Key([
        844617937539064431,
        8280782215217712600,
        776954566881514913,
        1946423943169448778,
    ]
    .map(F::from_canonical_u64));
    let k2 = Key([
        15434611863279822111,
        11975487827769517766,
        15368078704174133449,
        1970673199824226969,
    ]
    .map(F::from_canonical_u64));
    let k3 = Key([
        4947646911082557289,
        4015479196169929139,
        8997983193975654297,
        9607383237755583623,
    ]
    .map(F::from_canonical_u64));
    let k4 = Key([
        15508201873038097485,
        13226964191399612151,
        16289586894263066011,
        5039894867879804772,
    ]
    .map(F::from_canonical_u64));

    let v0 = U256::from_dec_str(
        "8163644824788514136399898658176031121905718480550577527648513153802600646339",
    )
    .unwrap();
    let v1 = U256::from_dec_str(
        "115792089237316195423570985008687907853269984665640564039457584007913129639934",
    )
    .unwrap();
    let v2 = U256::from_dec_str(
        "115792089237316195423570985008687907853269984665640564039457584007913129639935",
    )
    .unwrap();
    let v3 = U256::from_dec_str("7943875943875408").unwrap();
    let v4 = U256::from_dec_str(
        "35179347944617143021579132182092200136526168785636368258055676929581544372820",
    )
    .unwrap();

    smt.set(k0, v0);
    smt.set(k1, v1);
    smt.set(k2, v2);
    smt.set(k3, v3);
    smt.set(k4, v4);

    let expected_root = [
        13590506365193044307,
        13215874698458506886,
        4743455437729219665,
        1933616419393621600,
    ]
    .map(F::from_canonical_u64);
    assert_eq!(smt.root.elements, expected_root);

    let ser = smt.to_vec();
    assert_eq!(hash_serialize(&ser), smt.root);
}

#[test]
fn test_no_write_0() {
    let mut smt = Smt::<MemoryDb>::default();

    let k1 = Key(F::rand_array());
    let k2 = Key(F::rand_array());
    let v = U256(thread_rng().gen());
    smt.set(k1, v);
    let root = smt.root;
    smt.set(k2, U256::zero());
    assert_eq!(smt.root, root);

    let ser = smt.to_vec();
    assert_eq!(hash_serialize(&ser), smt.root);
}

#[test]
fn test_set_hash_first_level() {
    let mut smt = Smt::<MemoryDb>::default();

    let kvs = (0..128)
        .map(|_| {
            let k = Key(F::rand_array());
            let v = U256(random());
            smt.set(k, v);
            (k, v)
        })
        .collect::<Vec<_>>();
    for &(k, v) in &kvs {
        smt.set(k, v);
    }

    let first_level = smt.db.get_node(&Key(smt.root.elements)).unwrap();
    let mut hash_smt = Smt::<MemoryDb>::default();
    let zero = Bits {
        count: 1,
        packed: U256::zero(),
    };
    let one = Bits {
        count: 1,
        packed: U256::one(),
    };
    hash_smt.set_hash(
        zero,
        HashOut {
            elements: first_level.0[0..4].try_into().unwrap(),
        },
    );
    hash_smt.set_hash(
        one,
        HashOut {
            elements: first_level.0[4..8].try_into().unwrap(),
        },
    );

    assert_eq!(smt.root, hash_smt.root);

    let ser = hash_smt.to_vec();
    assert_eq!(hash_serialize(&ser), hash_smt.root);
}

#[test]
fn test_set_hash_order() {
    let mut smt = Smt::<MemoryDb>::default();

    let level = 4;

    let mut khs = (1..1 << level)
        .map(|i| {
            let k = Bits {
                count: level,
                packed: i.into(),
            };
            let hash = HashOut {
                elements: F::rand_array(),
            };
            (k, hash)
        })
        .collect::<Vec<_>>();
    for &(k, v) in &khs {
        smt.set_hash(k, v);
    }
    let key = loop {
        // Forgive my laziness
        let key = Key(F::rand_array());
        let keys = key.split();
        if (0..level).all(|i| !keys.get_bit(i)) {
            break key;
        }
    };
    let val = U256(random());
    smt.set(key, val);

    let mut second_smt = Smt::<MemoryDb>::default();
    khs.shuffle(&mut thread_rng());
    for (k, v) in khs {
        second_smt.set_hash(k, v);
    }
    second_smt.set(key, val);

    assert_eq!(smt.root, second_smt.root);

    let ser = second_smt.to_vec();
    assert_eq!(hash_serialize(&ser), second_smt.root);
}

#[test]
fn test_serialize_and_prune() {
    let mut smt = Smt::<MemoryDb>::default();

    for _ in 0..128 {
        let k = Key(F::rand_array());
        let v = U256(random());
        smt.set(k, v);
    }

    let ser = smt.to_vec();
    assert_eq!(hash_serialize(&ser), smt.root);

    let subset = {
        let r: u128 = random();
        smt.kv_store
            .keys()
            .enumerate()
            .filter_map(|(i, k)| if r & (1 << i) != 0 { Some(*k) } else { None })
            .collect::<Vec<_>>()
    };

    let pruned_ser = smt.serialize_and_prune(subset);
    assert_eq!(hash_serialize(&pruned_ser), smt.root);
    assert!(pruned_ser.len() <= ser.len());

    let trivial_ser = smt.serialize_and_prune::<Key, Vec<_>>(vec![]);
    assert_eq!(
        trivial_ser,
        vec![
            U256::zero(),
            U256::zero(),
            HASH_TYPE.into(),
            hashout2u(smt.root)
        ]
    );
    assert_eq!(hash_serialize(&trivial_ser), smt.root);
}
