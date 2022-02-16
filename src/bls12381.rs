/*
 * Copyright 2020 - MATTR Limited
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::utils::set_panic_hook;

use crate::{
    gen_rangeproof, gen_signature_message, BbsVerifyResponse, PoKOfSignatureProofMultiWrapper,
    PoKOfSignatureProofWrapper,
};
use bbs::prelude::*;
use pairing_plus::{
    bls12_381::{Bls12, Fr, G1, G2},
    hash_to_field::BaseFromRO,
    serdes::SerDes,
    CurveProjective,
};
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryInto,
    iter::FromIterator,
};
use wasm_bindgen::prelude::*;

use itertools::multizip;

wasm_impl!(
    /// Convenience struct for interfacing with JS.
    /// Option allows both of the keys to be JS::null
    /// or only one of them set.
    #[allow(non_snake_case)]
    #[derive(Debug, Deserialize, Serialize)]
    BlsKeyPair,
    publicKey: Option<Vec<u8>>,
    secretKey: Option<SecretKey>
);

wasm_impl!(
    Bls12381ToBbsRequest,
    keyPair: BlsKeyPair,
    messageCount: usize
);

wasm_impl!(
    BbsKeyPair,
    publicKey: PublicKey,
    secretKey: Option<SecretKey>,
    messageCount: usize
);

wasm_impl!(
    BlsBbsSignRequest,
    keyPair: BlsKeyPair,
    messages: Vec<Vec<u8>>
);

wasm_impl!(
    BlsBbsVerifyRequest,
    publicKey: DeterministicPublicKey,
    signature: Signature,
    messages: Vec<Vec<u8>>
);

wasm_impl!(
    BlsCreateProofRequest,
    signature: Signature,
    publicKey: DeterministicPublicKey,
    messages: Vec<Vec<u8>>,
    revealed: Vec<usize>,
    nonce: Vec<u8>
);

wasm_impl!(
    BlsVerifyProofContext,
    proof: PoKOfSignatureProofWrapper,
    publicKey: DeterministicPublicKey,
    messages: Vec<Vec<u8>>,
    nonce: Vec<u8>
);

wasm_impl!(
    BlsCreateProofMultiRequest,
    signature: Vec<Signature>,
    publicKey: Vec<DeterministicPublicKey>,
    messages: Vec<Vec<Vec<u8>>>,
    revealed: Vec<Vec<usize>>,
    nonce: Vec<u8>,
    equivs: Vec<Vec<(usize, usize)>>,
    range: Vec<Vec<(usize, usize, usize)>>
);

wasm_impl!(
    BlsVerifyProofMultiContext,
    proof: Vec<Vec<u8>>,
    publicKey: Vec<DeterministicPublicKey>,
    messages: Vec<Vec<Vec<u8>>>,
    revealed: Vec<Vec<usize>>,
    nonce: Vec<u8>,
    equivs: Vec<Vec<(usize, usize)>>,
    range: Vec<Vec<(usize, usize, usize)>>
);

/// Generate a BLS 12-381 key pair.
///
/// * seed: UIntArray with 32 element
///
/// returned vector is the concatenation of first the private key (32 bytes)
/// followed by the public key (96) bytes.
#[wasm_bindgen(js_name = generateBls12381G2KeyPair)]
pub async fn bls_generate_g2_key(seed: Option<Vec<u8>>) -> Result<JsValue, JsValue> {
    set_panic_hook();
    Ok(bls_generate_keypair::<G2>(seed))
}

/// Generate a BLS 12-381 key pair.
///
/// * seed: UIntArray with 32 element
///
/// returned vector is the concatenation of first the private key (32 bytes)
/// followed by the public key (48) bytes.
#[wasm_bindgen(js_name = generateBls12381G1KeyPair)]
pub async fn bls_generate_g1_key(seed: Option<Vec<u8>>) -> Result<JsValue, JsValue> {
    set_panic_hook();
    Ok(bls_generate_keypair::<G1>(seed))
}

/// Get the BBS public key associated with the private key
#[wasm_bindgen(js_name = bls12381toBbs)]
pub async fn bls_to_bbs_key(request: JsValue) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let request: Bls12381ToBbsRequest = request.try_into()?;
    if request.messageCount == 0 {
        return Err(JsValue::from_str("Failed to convert key"));
    }
    if let Some(dpk_bytes) = request.keyPair.publicKey {
        let dpk = DeterministicPublicKey::from(array_ref![dpk_bytes, 0, G2_COMPRESSED_SIZE]);
        let pk = dpk.to_public_key(request.messageCount)?;
        let key_pair = BbsKeyPair {
            publicKey: pk,
            secretKey: request.keyPair.secretKey,
            messageCount: request.messageCount,
        };
        Ok(serde_wasm_bindgen::to_value(&key_pair).unwrap())
    } else if let Some(s) = request.keyPair.secretKey {
        let (dpk, sk) = DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(s))).unwrap();
        let pk = dpk.to_public_key(request.messageCount)?;
        let key_pair = BbsKeyPair {
            publicKey: pk,
            secretKey: Some(sk),
            messageCount: request.messageCount,
        };
        Ok(serde_wasm_bindgen::to_value(&key_pair).unwrap())
    } else {
        Err(JsValue::from_str("No key is specified"))
    }
}

/// Signs a set of messages with a BLS 12-381 key pair and produces a BBS signature
#[wasm_bindgen(js_name = blsSign)]
pub async fn bls_sign(request: JsValue) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let request: BlsBbsSignRequest = request.try_into()?;
    let dpk_bytes = request.keyPair.publicKey.unwrap();
    let dpk = DeterministicPublicKey::from(array_ref![dpk_bytes, 0, G2_COMPRESSED_SIZE]);
    let pk_res = dpk.to_public_key(request.messages.len());
    let pk;
    match pk_res {
        Err(_) => return Err(JsValue::from_str("Failed to convert key")),
        Ok(p) => pk = p,
    };
    if request.keyPair.secretKey.is_none() {
        return Err(JsValue::from_str("Failed to sign"));
    }
    let messages = request
        .messages
        .iter()
        .map(|m| gen_signature_message(m))
        .collect::<Result<Vec<_>, _>>()?;
    match Signature::new(
        messages.as_slice(),
        &request.keyPair.secretKey.unwrap(),
        &pk,
    ) {
        Ok(sig) => Ok(serde_wasm_bindgen::to_value(&sig).unwrap()),
        Err(e) => Err(JsValue::from(&format!("{:?}", e))),
    }
}

/// Verifies a BBS+ signature for a set of messages with a with a BLS 12-381 public key
#[wasm_bindgen(js_name = blsVerify)]
pub async fn bls_verify(request: JsValue) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let res = request.try_into();
    let result: BlsBbsVerifyRequest;
    match res {
        Ok(r) => result = r,
        Err(e) => {
            return Ok(serde_wasm_bindgen::to_value(&BbsVerifyResponse {
                verified: false,
                error: Some(format!("{:?}", e)),
            })
            .unwrap())
        }
    };
    if result.messages.is_empty() {
        return Ok(serde_wasm_bindgen::to_value(&BbsVerifyResponse {
            verified: false,
            error: Some("Messages cannot be empty".to_string()),
        })
        .unwrap());
    }
    let pk = result.publicKey.to_public_key(result.messages.len())?;
    let messages = result
        .messages
        .iter()
        .map(|m| gen_signature_message(m))
        .collect::<Result<Vec<_>, _>>()?;
    match result.signature.verify(messages.as_slice(), &pk) {
        Err(e) => Ok(serde_wasm_bindgen::to_value(&BbsVerifyResponse {
            verified: false,
            error: Some(format!("{:?}", e)),
        })
        .unwrap()),
        Ok(b) => Ok(serde_wasm_bindgen::to_value(&BbsVerifyResponse {
            verified: b,
            error: None,
        })
        .unwrap()),
    }
}

/// Creates a BBS+ PoK
#[wasm_bindgen(js_name = blsCreateProof)]
pub async fn bls_create_proof(request: JsValue) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let request: BlsCreateProofRequest = request.try_into()?;
    if request.revealed.iter().any(|r| *r > request.messages.len()) {
        return Err(JsValue::from("revealed value is out of bounds"));
    }
    let pk = request.publicKey.to_public_key(request.messages.len())?;
    let revealed: BTreeSet<usize> = BTreeSet::from_iter(request.revealed.into_iter());
    let mut messages = Vec::new();
    for i in 0..request.messages.len() {
        if revealed.contains(&i) {
            messages.push(ProofMessage::Revealed(SignatureMessage::hash(
                &request.messages[i],
            )));
        } else {
            messages.push(ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(
                SignatureMessage::hash(&request.messages[i]),
            )));
        }
    }
    match PoKOfSignature::init(&request.signature, &pk, messages.as_slice()) {
        Err(e) => return Err(JsValue::from(&format!("{:?}", e))),
        Ok(pok) => {
            let mut challenge_bytes = pok.to_bytes();
            if request.nonce.is_empty() {
                challenge_bytes.extend_from_slice(&[0u8; FR_COMPRESSED_SIZE]);
            } else {
                let nonce = ProofNonce::hash(&request.nonce);
                challenge_bytes.extend_from_slice(nonce.to_bytes_uncompressed_form().as_ref());
            }
            let challenge_hash = ProofChallenge::hash(&challenge_bytes);
            match pok.gen_proof(&challenge_hash) {
                Ok(proof) => {
                    let out =
                        PoKOfSignatureProofWrapper::new(request.messages.len(), &revealed, proof);
                    Ok(serde_wasm_bindgen::to_value(&out).unwrap())
                }
                Err(e) => Err(JsValue::from(&format!("{:?}", e))),
            }
        }
    }
}

/// Verify a BBS+ PoK
#[wasm_bindgen(js_name = blsVerifyProof)]
pub async fn bls_verify_proof(request: JsValue) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let res = serde_wasm_bindgen::from_value::<BlsVerifyProofContext>(request);
    let request: BlsVerifyProofContext;
    match res {
        Ok(r) => request = r,
        Err(e) => {
            return Ok(serde_wasm_bindgen::to_value(&BbsVerifyResponse {
                verified: false,
                error: Some(format!("{:?}", e)),
            })
            .unwrap())
        }
    };

    let nonce = if request.nonce.is_empty() {
        ProofNonce::default()
    } else {
        ProofNonce::hash(&request.nonce)
    };
    let message_count = u16::from_be_bytes(*array_ref![request.proof.bit_vector, 0, 2]) as usize;
    let pk = request.publicKey.to_public_key(message_count)?;
    let messages = request.messages.clone();
    let (revealed, proof) = request.proof.unwrap();
    let proof_request = ProofRequest {
        revealed_messages: revealed,
        verification_key: pk,
    };

    let revealed_vec = proof_request
        .revealed_messages
        .iter()
        .collect::<Vec<&usize>>();
    let mut revealed_messages = BTreeMap::new();
    for i in 0..revealed_vec.len() {
        revealed_messages.insert(
            *revealed_vec[i],
            SignatureMessage::hash(messages[i].clone()),
        );
    }

    let signature_proof = SignatureProof {
        revealed_messages,
        proof,
    };

    Ok(serde_wasm_bindgen::to_value(&BbsVerifyResponse {
        verified: Verifier::verify_signature_pok(&proof_request, &signature_proof, &nonce).is_ok(),
        error: None,
    })
    .unwrap())
}

fn bls_generate_keypair<G: CurveProjective<Engine = Bls12, Scalar = Fr> + SerDes>(
    seed: Option<Vec<u8>>,
) -> JsValue {
    let seed_data = match seed {
        Some(s) => s.to_vec(),
        None => {
            let mut rng = thread_rng();
            let mut s = vec![0u8, 32];
            rng.fill_bytes(s.as_mut_slice());
            s
        }
    };

    let sk = gen_sk(seed_data.as_slice());
    let mut pk = G::one();
    pk.mul_assign(sk);

    let mut pk_bytes = Vec::new();
    pk.serialize(&mut pk_bytes, true).unwrap();

    let keypair = BlsKeyPair {
        publicKey: Some(pk_bytes),
        secretKey: Some(SecretKey::from(sk)),
    };
    serde_wasm_bindgen::to_value(&keypair).unwrap()
}

fn gen_sk(msg: &[u8]) -> Fr {
    use sha2::digest::generic_array::{typenum::U48, GenericArray};
    const SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";
    // copy of `msg` with appended zero byte
    let mut msg_prime = Vec::<u8>::with_capacity(msg.as_ref().len() + 1);
    msg_prime.extend_from_slice(msg.as_ref());
    msg_prime.extend_from_slice(&[0]);
    // `result` has enough length to hold the output from HKDF expansion
    let mut result = GenericArray::<u8, U48>::default();
    assert!(hkdf::Hkdf::<sha2::Sha256>::new(Some(SALT), &msg_prime[..])
        .expand(&[0, 48], &mut result)
        .is_ok());
    Fr::from_okm(&result)
}

/// Creates a BBS+ PoK from termwise-encoded multiple credentials
#[wasm_bindgen(js_name = blsCreateProofMulti)]
pub async fn bls_create_proof_multi(request: JsValue) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let request: BlsCreateProofMultiRequest = request.try_into()?;
    let num_of_inputs = request.messages.len();

    if [
        request.signature.len(),
        request.revealed.len(),
        request.publicKey.len(),
    ]
    .iter()
    .any(|&x| x != num_of_inputs)
    {
        return Err(JsValue::from(
            "numbers of messages, signature, revealed, and publicKey must be the same",
        ));
    }

    let mut poks: Vec<PoKOfSignature> = Vec::with_capacity(num_of_inputs);
    let mut message_counts: Vec<usize> = Vec::with_capacity(num_of_inputs);
    let mut range_commitments_vec: Vec<Vec<PoKOfCommitment>> = Vec::with_capacity(num_of_inputs);

    // generate blindings and hashmaps based on request.equivs
    let equiv_blindings: Vec<ProofNonce> = request
        .equivs
        .iter()
        .map(|_| ProofNonce::random())
        .collect();
    let mut equivs_map: HashMap<(usize, usize), usize> = HashMap::new();
    for (i, eq) in request.equivs.iter().enumerate() {
        for &e in eq {
            equivs_map.insert(e, i);
        }
    }

    // (1) commit
    for (i, (r_messages, r_signature, r_revealed, r_pk, r_range)) in multizip((
        request.messages,
        request.signature,
        request.revealed,
        request.publicKey,
        request.range,
    ))
    .enumerate()
    {
        if r_revealed.iter().any(|r| *r > r_messages.len()) {
            return Err(JsValue::from("revealed value is out of bounds"));
        }
        let pk = r_pk.to_public_key(r_messages.len())?;
        let revealed: BTreeSet<&usize> = r_revealed.iter().collect();

        let messages = r_messages
            .iter()
            .map(|m| gen_signature_message(m))
            .collect::<Result<Vec<_>, _>>()?;

        // for range proofs
        // generate blindings of integer m's for range proofs
        let blinding_ms: HashMap<usize, ProofNonce> = r_range
            .iter()
            .map(|&(range_idx, _, _)| (range_idx, ProofNonce::random()))
            .collect();
        let rs: HashMap<usize, ProofNonce> = r_range
            .iter()
            .map(|&(range_idx, _, _)| (range_idx, ProofNonce::random()))
            .collect();
        // generate Pedersen commitments for range proofs
        let range_commitment: Vec<PoKOfCommitment> = r_range
            .iter()
            .map(|&(range_idx, _, _)| {
                let m = messages[range_idx];

                
                let blinding_m = blinding_ms[&range_idx];
                let r = rs[&range_idx];
                PoKOfCommitment::init(range_idx, &pk.h[0], &pk.h0, &m, &blinding_m, &r)
            })
            .collect();
        let cs: Vec<_> = range_commitment.iter().map(|c| c.c).collect();
        // generate bulletproofs
        let bulletproofs: Result<Vec<_>, _> = r_range
            .iter()
            .zip(cs)
            .map(|(&(range_idx, min, max), c)| {
                let m = messages[range_idx];
                let r = rs[&range_idx];
                let min: u64 = min.try_into().unwrap();
                let max: u64 = max.try_into().unwrap();
                gen_rangeproof(
                    m.as_ref(),
                    r.as_ref(),
                    min,
                    max,
                    32,
                    pk.h[0].as_ref(),
                    pk.h0.as_ref(),
                    c.as_ref(),
                )
            })
            .collect();

        let messages: Vec<ProofMessage> = messages
            .iter()
            .enumerate()
            .map(|(j, &m)| {
                match (
                    revealed.contains(&j),
                    equivs_map.get(&(i, j)),
                    blinding_ms.get(&j),
                ) {
                    (true, None, None) => ProofMessage::Revealed(m),
                    (true, Some(&k), None) => {
                        ProofMessage::Hidden(HiddenMessage::ExternalBlinding(m, equiv_blindings[k]))
                    }
                    (true, None, Some(&blinding_m)) => {
                        ProofMessage::Hidden(HiddenMessage::ExternalBlinding(m, blinding_m))
                    }
                    _ => ProofMessage::Hidden(HiddenMessage::ProofSpecificBlinding(m)),
                }
            })
            .collect();

        match PoKOfSignature::init(&r_signature, &pk, messages.as_slice()) {
            Err(e) => return Err(JsValue::from(&format!("{:?}", e))),
            Ok(pok) => {
                poks.push(pok);
                message_counts.push(r_messages.len());
                range_commitments_vec.push(range_commitment);
            }
        }
    }

    // (2) challenge
    //     ch = H(bases_1, cmts_1, ..., bases_n, cmts_n, nonce)
    let nonce = ProofNonce::hash(&request.nonce);
    let range_commitments_byte = range_commitments_vec
        .iter()
        .flat_map(|c| {
            c.iter()
                .flat_map(|pokoc| pokoc.to_bytes())
                .collect::<Vec<u8>>()
        })
        .collect::<Vec<u8>>();

    let challenge_hash =
        Prover::create_challenge_hash(&poks, Some(&[&range_commitments_byte]), &nonce).unwrap();

    // (3) response
    let mut proofs: Vec<PoKOfSignatureProofMultiWrapper> = Vec::with_capacity(num_of_inputs);
    for (pok, message_count, range_commitments) in
        multizip((poks, message_counts, range_commitments_vec))
    {
        match (
            pok.gen_proof(&challenge_hash),
            range_commitments
                .into_iter()
                .map(|pokoc| pokoc.gen_proof(&challenge_hash))
                .collect(),
        ) {
            (Ok(proof), Ok(range_commitment_proofs)) => {
                let out = PoKOfSignatureProofMultiWrapper::new(
                    message_count,
                    proof,
                    range_commitment_proofs,
                );
                proofs.push(out);
            }
            (Err(e), _) => return Err(JsValue::from(&format!("{:?}", e))),
            (_, Err(e)) => return Err(JsValue::from(&format!("{:?}", e))),
        }
    }

    // CBOR-encodes each proof
    let cbor_proofs: Vec<Vec<u8>> = proofs
        .iter()
        .map(|proof| serde_cbor::ser::to_vec_packed(proof).unwrap())
        .collect();

    // return JS-array of CBOR-encoded proofs
    Ok(serde_wasm_bindgen::to_value(&cbor_proofs).unwrap())
}

fn gen_verification_response(verified: bool, error: Option<String>) -> Result<JsValue, JsValue> {
    Ok(serde_wasm_bindgen::to_value(&BbsVerifyResponse { verified, error }).unwrap())
}

/// Verify a BBS+ PoK from termwise-encoded multiple credentials
#[wasm_bindgen(js_name = blsVerifyProofMulti)]
pub async fn bls_verify_proof_multi(request: JsValue) -> Result<JsValue, JsValue> {
    set_panic_hook();
    let res = serde_wasm_bindgen::from_value::<BlsVerifyProofMultiContext>(request);
    let request: BlsVerifyProofMultiContext;
    match res {
        Ok(r) => request = r,
        Err(e) => return gen_verification_response(false, Some(format!("{:?}", e))),
    };

    // check the numbers of input parameters
    let num_of_inputs = request.messages.len();
    if [
        request.proof.len(),
        request.revealed.len(),
        request.publicKey.len(),
    ]
    .iter()
    .any(|&x| x != num_of_inputs)
    {
        return gen_verification_response(
            false,
            Some(
                "numbers of messages, proof, revealed, and publicKey must be the same".to_string(),
            ),
        );
    }
    if num_of_inputs == 0 {
        return gen_verification_response(
            false,
            Some(
                "at least one tuple of messages, proof, revealed, and publicKey must be given"
                    .to_string(),
            ),
        );
    }

    let nonce = if request.nonce.is_empty() {
        ProofNonce::default()
    } else {
        ProofNonce::hash(&request.nonce)
    };

    // Prepare partial_hidden_set,
    //   each of which contains hidden indices included in equivalence classes;
    // This **partial** set will be integrated with revealed_vec to calculate hidden_orig_vec
    let mut partial_hidden_set: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); num_of_inputs];
    for (_, eq) in request.equivs.iter().enumerate() {
        for &(cred_i, term_i) in eq {
            partial_hidden_set[cred_i].insert(term_i);
        }
    }

    // (1) prepare inputs for challenge hashing
    //     ch = H(bases_1, cmts_1, ..., bases_n, cmts_n, nonce)
    let mut proof_requests: Vec<ProofRequest> = Vec::with_capacity(num_of_inputs);
    let mut proofs: Vec<SignatureProof> = Vec::with_capacity(num_of_inputs);
    let mut hidden_vecs: Vec<Vec<usize>> = Vec::with_capacity(num_of_inputs);
    let mut range_commitments_vec: Vec<(Vec<PoKOfCommitmentProof>, PublicKey)> =
        Vec::with_capacity(num_of_inputs);
    for (i, (messages, revealed_vec, cbor_proof, dpk)) in multizip((
        request.messages,
        request.revealed,
        request.proof,
        request.publicKey,
    ))
    .enumerate()
    {
        // decode CBOR
        let count_and_proof: PoKOfSignatureProofMultiWrapper =
            serde_cbor::from_slice(&cbor_proof).unwrap();
        let proof = count_and_proof.proof;
        let range_commitment_proofs = count_and_proof.range_commitment_proofs;
        let pk = dpk.to_public_key(count_and_proof.message_count)?;

        // indices of the range-proved messages
        let range_index_set: BTreeSet<usize> =
            range_commitment_proofs.iter().map(|p| p.i).collect();

        // prepare revealed_set and hidden_vecs
        // e.g., all_set = {0, 1, 2, 3, 4}        // there are originally four messages: m_0, m_1, m_2, m_3, m_4
        //       pre_revealed_set = {0, 2, 3, 4}  // candidates not to be hidden indicated by reveal indices
        //       partial_hidden_set = {3}         // m_3 is hidden and proved to be equivallent with the other
        //       range_index_set = {4}            // m_4 is hidden and proved its range
        //       revealed_set = {0, 2}            // revealed messages are m_0 and m_2
        //       hidden_vec = [1, 3, 4]           // hidden messages are m_1, m_3, and m_4
        let all_set: BTreeSet<usize> = (0..count_and_proof.message_count).collect();
        let pre_revealed_set: BTreeSet<usize> = revealed_vec.clone().into_iter().collect();
        let revealed_set: BTreeSet<usize> = pre_revealed_set
            .difference(
                &partial_hidden_set[i]
                    .union(&range_index_set)
                    .cloned()
                    .collect(),
            )
            .cloned()
            .collect();
        let hidden_vec: Vec<usize> = all_set.difference(&revealed_set).cloned().collect();

        // for range proofs
        // check the equality of the hidden message in BBS+ proof and the commited value for range proofs
        if range_commitment_proofs
            .iter()
            .map(|p| {
                let resp_in_cmt = p.get_resp_for_message();
                let resp_in_proof =
                    proof.get_resp_for_message(hidden_vec.iter().position(|x| *x == p.i).unwrap());

                match (resp_in_cmt, resp_in_proof) {
                    (Ok(rc), Ok(rp)) => rc == rp,
                    _ => false,
                }
            })
            .any(|b| !b)
        {
            return gen_verification_response(
                false,
                Some("invalid commitment for range proofs".to_string()),
            );
        }

        // store for challenge hash computation later
        hidden_vecs.push(hidden_vec);
        range_commitments_vec.push((range_commitment_proofs, pk.clone()));

        // prepare revealed_messages
        // e.g, index_map = [0, 2, 3]   // m'_0 = m_0, m'_1 = m_2, m'_2 -> m_3
        //      revealed_messages = { "0": H(m'_0), "2": H(m'_1)}   // m_3 is hidden (its equality is proved)
        let index_map = pre_revealed_set.iter().collect::<Vec<&usize>>();
        let revealed_messages: BTreeMap<usize, SignatureMessage> = messages
            .iter()
            .map(|m| gen_signature_message(m))
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .enumerate()
            .filter_map(|(m_index, &m)| {
            let m_index_orig = index_map[m_index];
            if revealed_set.contains(m_index_orig) {
                    Some((*m_index_orig, m))
                } else {
                    None
            }
            })
            .collect();


        // prepare proof_requests
        let proof_request = ProofRequest {
            revealed_messages: revealed_set,
            verification_key: pk,
        };
        proof_requests.push(proof_request);

        // prepare proofs
        let signature_proof = SignatureProof {
            revealed_messages,
            proof,
        };
        proofs.push(signature_proof);
    }

    // equality checks
    let mut resps: Vec<BTreeSet<SignatureMessage>> = request
        .equivs
        .iter()
        .map(|_| BTreeSet::<SignatureMessage>::new())
        .collect();
    for (anon_i, eq) in request.equivs.iter().enumerate() {
        for &(cred_i, term_i) in eq {
            let resp = proofs[cred_i].proof.get_resp_for_message(
                hidden_vecs[cred_i]
                    .iter()
                    .position(|x| *x == term_i)
                    .unwrap(),
            );
            match resp {
                Ok(r) => resps[anon_i].insert(r),
                Err(e) => {
                    return gen_verification_response(
                        false,
                        Some(format!("failed verification of message equality: {}", e)),
                    )
                }
            };
            if resps[anon_i].len() >= 2 {
                return gen_verification_response(
                    false,
                    Some("failed verification of message equality".to_string()),
                );
            }
        }
    }

    // (2) challenge hashing
    let range_commitments_byte = range_commitments_vec
        .iter()
        .flat_map(|(c, pk)| {
            c.iter()
                .flat_map(|pokoc| pokoc.get_bytes_for_challenge(&pk.h[0], &pk.h0))
                .collect::<Vec<u8>>()
        })
        .collect::<Vec<u8>>();

    let challenge = Verifier::create_challenge_hash(
        &proofs,
        &proof_requests,
        &nonce,
        Some(&[&range_commitments_byte]),
    )
    .unwrap();


    // (3) verify
    let results: Vec<Result<Vec<SignatureMessage>, BBSError>> = proofs
        .iter()
        .zip(proof_requests.iter())
        .map(|(signature_proof, proof_request)| {
            match signature_proof.proof.verify(
                &proof_request.verification_key,
                &signature_proof.revealed_messages,
                &challenge,
            )? {
                PoKOfSignatureProofStatus::Success => Ok(signature_proof
                    .revealed_messages
                    .iter()
                    .map(|(_, m)| *m)
                    .collect::<Vec<SignatureMessage>>()),
                e => Err(BBSErrorKind::InvalidProof { status: e }.into()),
            }
        })
        .collect();

    let error_msg_sig = results
        .iter()
        .map(|r| match r {
            Ok(_) => "".to_string(),
            Err(e) => e.to_string(),
        })
        .collect::<String>();

    let results_range: Vec<Result<PoKOfCommitmentProofStatus, BBSError>> = range_commitments_vec
        .iter()
        .flat_map(|(cs, pk)| {
            cs.iter()
                .map(move |c| c.verify(&[pk.h[0], pk.h0], &challenge))
        })
        .collect();

    let error_msg_range = results_range
        .iter()
        .map(|r| match r {
            Ok(_) => "".to_string(),
            Err(e) => e.to_string(),
        })
        .collect::<String>();

    let error_msg = format!("{}{}", error_msg_sig, error_msg_range);
    if error_msg.is_empty() {
        gen_verification_response(true, None)
    } else {
        gen_verification_response(false, Some(format!("{:?}", error_msg)))
    }
}
