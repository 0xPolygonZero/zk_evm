use ethereum_types::U256;
use plonky2::field::types::{Field, Sample};
use rand::{thread_rng, Rng};

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

    let ser = smt.serialize();
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

    let ser = smt.serialize();
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

    let ser = smt.serialize();
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

    let ser = smt.serialize();
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

    let ser = smt.serialize();
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

    let ser = smt.serialize();
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

    let ser = smt.serialize();
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

    let ser = smt.serialize();
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

    let ser = smt.serialize();
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

    let ser = smt.serialize();
    assert_eq!(hash_serialize(&ser), smt.root);
}

#[test]
fn test_go() {
    let ser = [
        "0",
        "0",
        "1",
        "0",
        "8",
        "2",
        "51276673645122424560949981062119584099169321435701673909816643388847445641846",
        "6",
        "1",
        "11",
        "32",
        "1",
        "0",
        "14",
        "1",
        "17",
        "29",
        "2",
        "28328758047521851759096085189052303612615597394166634881068456545690003780795",
        "109999999999999999739980",
        "1",
        "23",
        "0",
        "1",
        "26",
        "29",
        "2",
        "53482609480495366142179125726330190811455879276251518477812432356269042524949",
        "10001000000000000000000",
        "2",
        "52888520349817282774049741659916291311644451235491655529365153687612724986736",
        "96161719145413027019141721112028853846784104389878865383823587385856726631878",
        "1",
        "35",
        "38",
        "2",
        "109936312484913552521013697136727361637070124128247912964153490744520112944201",
        "12",
        "2",
        "60599236333385617412379752144535205983387298893900492837953963722899163396573",
        "26995388229280533633220990022959262540330760104421443229184402759527096867961",
        "0",
        "0",
        "0",
        "0",
        "106",
        "248",
        "104",
        "5",
        "10",
        "131",
        "30",
        "132",
        "128",
        "148",
        "160",
        "160",
        "160",
        "160",
        "160",
        "160",
        "160",
        "160",
        "160",
        "160",
        "160",
        "160",
        "160",
        "160",
        "160",
        "160",
        "160",
        "160",
        "160",
        "160",
        "136",
        "13",
        "224",
        "182",
        "179",
        "167",
        "100",
        "0",
        "0",
        "128",
        "37",
        "160",
        "155",
        "171",
        "141",
        "183",
        "215",
        "46",
        "75",
        "66",
        "203",
        "168",
        "177",
        "23",
        "136",
        "62",
        "22",
        "135",
        "41",
        "102",
        "186",
        "232",
        "228",
        "87",
        "5",
        "130",
        "222",
        "110",
        "208",
        "6",
        "94",
        "140",
        "54",
        "161",
        "160",
        "18",
        "86",
        "212",
        "77",
        "152",
        "44",
        "117",
        "224",
        "171",
        "122",
        "25",
        "246",
        "26",
        "183",
        "138",
        "250",
        "158",
        "8",
        "157",
        "81",
        "200",
        "104",
        "111",
        "223",
        "190",
        "224",
        "133",
        "165",
        "237",
        "93",
        "143",
        "248",
        "4",
        "2",
        "128",
        "45",
        "264",
        "1",
        "26002",
        "0",
        "0",
        "0",
        "0",
        "0",
        "0",
    ]
    .iter()
    .map(|x| U256::from_dec_str(x).unwrap())
    .collect::<Vec<_>>();
    dbg!(hash_serialize(&ser));
}
