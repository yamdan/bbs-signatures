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

//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]
extern crate wasm_bindgen_test;
use bbs::prelude::*;
use wasm::prelude::*;
use wasm::BbsVerifyResponse;
use wasm::PoKOfSignatureProofMultiWrapper;
// use wasm::log;
use arrayref::array_ref;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[allow(non_snake_case)]
#[wasm_bindgen_test]
async fn bls_public_key_to_bbs_key_test() {
    let (dpk, _) = DeterministicPublicKey::new(None);
    let request = Bls12381ToBbsRequest {
        keyPair: BlsKeyPair {
            publicKey: Some(dpk.to_bytes_compressed_form().to_vec()),
            secretKey: None,
        },
        messageCount: 5,
    };
    let js_value = serde_wasm_bindgen::to_value(&request).unwrap();
    let bbs_res = bls_to_bbs_key(js_value).await;
    assert!(bbs_res.is_ok());
    let bbs = bbs_res.unwrap();
    assert!(bbs.is_object());
    let public_key_res = serde_wasm_bindgen::from_value::<BbsKeyPair>(bbs);
    assert!(public_key_res.is_ok());
    let bbsKeyPair = public_key_res.unwrap();
    assert_eq!(bbsKeyPair.publicKey.to_bytes_compressed_form().len(), 388);
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
async fn bls_secret_key_to_bbs_key_test() {
    let (_, sk) = DeterministicPublicKey::new(None);
    let request = Bls12381ToBbsRequest {
        keyPair: BlsKeyPair {
            publicKey: None,
            secretKey: Some(sk),
        },
        messageCount: 5,
    };
    let js_value = serde_wasm_bindgen::to_value(&request).unwrap();
    let bbs_res = bls_to_bbs_key(js_value).await;
    assert!(bbs_res.is_ok());
    let bbs = bbs_res.unwrap();
    assert!(bbs.is_object());
    let public_key_res = serde_wasm_bindgen::from_value::<BbsKeyPair>(bbs);
    assert!(public_key_res.is_ok());
    let pk_bytes = public_key_res.unwrap();
    assert_eq!(pk_bytes.publicKey.to_bytes_compressed_form().len(), 388);
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
async fn bls_generate_key_from_seed_test() {
    let key = bls_generate_g2_key(Some(vec![0u8; 16])).await.unwrap();

    assert!(key.is_object());
    let obj = js_sys::Object::try_from(&key);
    assert!(obj.is_some());
    let obj = obj.unwrap();
    let entries = js_sys::Object::entries(&obj).to_vec();
    assert_eq!(entries.len(), 2);
    let keys = js_sys::Object::keys(&obj);
    let values = js_sys::Object::values(&obj);
    assert_eq!(keys.get(0), "publicKey");
    assert_eq!(keys.get(1), "secretKey");
    let public_key_res = serde_wasm_bindgen::from_value::<Vec<u8>>(values.get(0));
    let secret_key_res = serde_wasm_bindgen::from_value::<Vec<u8>>(values.get(1));
    assert!(public_key_res.is_ok());
    assert!(secret_key_res.is_ok());
    let public_key = public_key_res.unwrap();
    let secret_key = secret_key_res.unwrap();
    assert_eq!(public_key.len(), 96);
    assert_eq!(
        public_key,
        vec![
            180, 23, 7, 111, 46, 125, 2, 98, 246, 216, 152, 143, 211, 97, 181, 151, 222, 57, 210,
            214, 209, 232, 161, 117, 141, 179, 142, 31, 100, 177, 61, 56, 98, 188, 127, 59, 155,
            155, 24, 28, 202, 70, 141, 93, 26, 221, 216, 189, 7, 70, 49, 66, 223, 161, 28, 147,
            230, 62, 217, 165, 119, 187, 51, 233, 42, 249, 219, 62, 242, 24, 74, 67, 114, 156, 32,
            51, 212, 205, 110, 172, 195, 102, 121, 11, 192, 96, 85, 205, 226, 139, 248, 208, 202,
            85, 9, 145
        ]
    );
    assert_eq!(secret_key.len(), 32);
    assert_eq!(
        secret_key,
        vec![
            18, 252, 35, 29, 203, 163, 152, 132, 177, 59, 46, 170, 55, 231, 184, 150, 20, 44, 51,
            147, 188, 46, 118, 36, 66, 145, 240, 37, 56, 41, 65, 3
        ]
    );
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
async fn bls_generate_key_test() {
    let key = bls_generate_g2_key(None).await.unwrap();

    assert!(key.is_object());
    let obj = js_sys::Object::try_from(&key);
    assert!(obj.is_some());
    let obj = obj.unwrap();
    let entries = js_sys::Object::entries(&obj).to_vec();
    assert_eq!(entries.len(), 2);
    let keys = js_sys::Object::keys(&obj);
    let values = js_sys::Object::values(&obj);
    assert_eq!(keys.get(0), "publicKey");
    assert_eq!(keys.get(1), "secretKey");
    let publicKey = js_sys::Array::from(&values.get(0));
    let secretKey = js_sys::Array::from(&values.get(1));
    assert_eq!(publicKey.length(), 96);
    assert_eq!(secretKey.length(), 32);
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub async fn bls_single_whole_success_test() {
    // issue credential
    let key_pair_js0 = bls_generate_g2_key(None).await.unwrap();
    let messages0 = vec![
        b"Message[0,0]".to_vec(),
        b"Message[0,1]".to_vec(),
        b"Message_EQ_0".to_vec(),
        b"Message_EQ_0".to_vec(),
        b"Message[0,4]".to_vec(),
    ];
    let sign_request0 = BlsBbsSignRequest {
        keyPair: serde_wasm_bindgen::from_value::<BlsKeyPair>(key_pair_js0.clone()).unwrap(),
        messages: messages0.clone(),
    };
    let sign_request_js0 = serde_wasm_bindgen::to_value(&sign_request0).unwrap();
    let signature_js0 = bls_sign(sign_request_js0).await.unwrap();
    let signature0 = serde_wasm_bindgen::from_value::<Signature>(signature_js0).unwrap();

    // verify credential
    let dpk_bytes0 = serde_wasm_bindgen::from_value::<BlsKeyPair>(key_pair_js0.clone())
        .unwrap()
        .publicKey
        .unwrap();
    let dpk0 = DeterministicPublicKey::from(array_ref![dpk_bytes0, 0, G2_COMPRESSED_SIZE]);
    let verify_request0 = BlsBbsVerifyRequest {
        publicKey: dpk0,
        signature: signature0.clone(),
        messages: messages0.clone(),
    };
    let verify_request_js0 = serde_wasm_bindgen::to_value(&verify_request0).unwrap();
    let verify_result_js0 = bls_verify(verify_request_js0).await.unwrap();
    let verify_result0 =
        serde_wasm_bindgen::from_value::<BbsVerifyResponse>(verify_result_js0).unwrap();
    assert!(verify_result0.verified);

    // derive credential
    let revealed0 = vec![0, 1, 2, 3];
    let eq0 = vec![(0, 2), (0, 3)]; // equivalence class corresponding to "Message_EQ_0"
    let derive_proof_request = BlsCreateProofMultiRequest {
        signature: vec![signature0],
        publicKey: vec![dpk0],
        messages: vec![messages0],
        revealed: vec![revealed0.clone()],
        nonce: vec![0],
        equivs: vec![eq0],
    };
    let derive_proof_request_js = serde_wasm_bindgen::to_value(&derive_proof_request).unwrap();
    let derived_proofs_js = bls_create_proof_multi(derive_proof_request_js).await;
    assert!(derived_proofs_js.is_ok(), "{:?}", derived_proofs_js);
    let derived_proofs = serde_wasm_bindgen::from_value::<Vec<PoKOfSignatureProofMultiWrapper>>(
        derived_proofs_js.unwrap(),
    )
    .unwrap();
    assert_eq!(derived_proofs.len(), 1);

    // verify derived proof
    let revealed_messages0 = vec![
        b"Message[0,0]".to_vec(), // revealed
        b"Message[0,1]".to_vec(), // revealed
        b"___DUMMY____".to_vec(), // hidden with proof of equality; was "Message_EQ_0"
        b"___DUMMY____".to_vec(), // hidden with proof of equality; was "Message_EQ_0"
                                  // hidden;                        was "Message[0,4]"
    ];
    let eqv0 = vec![(0, 2), (0, 3)]; // equivalence class corresponding to "___DUMMY_EQ_0_"
    let verify_proof_request = BlsVerifyProofMultiContext {
        proof: derived_proofs,
        publicKey: vec![dpk0],
        messages: vec![revealed_messages0],
        revealed: vec![revealed0],
        nonce: vec![0],
        equivs: vec![eqv0],
    };
    let verify_proof_request_js = serde_wasm_bindgen::to_value(&verify_proof_request).unwrap();
    let verify_proof_result_js = bls_verify_proof_multi(verify_proof_request_js)
        .await
        .unwrap();
    let verify_proof_result =
        serde_wasm_bindgen::from_value::<BbsVerifyResponse>(verify_proof_result_js).unwrap();
    assert!(
        verify_proof_result.verified,
        "{:?}",
        verify_proof_result.error
    );
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub async fn bls_single_invalid_derive_test() {
    // issue credential
    let key_pair_js0 = bls_generate_g2_key(None).await.unwrap();
    let messages0 = vec![
        b"Message[0,0]".to_vec(),
        b"Message[0,1]".to_vec(),
        b"Message[0,2]".to_vec(),
        b"Message[0,3]".to_vec(),
        b"Message[0,4]".to_vec(),
    ];
    let sign_request0 = BlsBbsSignRequest {
        keyPair: serde_wasm_bindgen::from_value::<BlsKeyPair>(key_pair_js0.clone()).unwrap(),
        messages: messages0.clone(),
    };
    let sign_request_js0 = serde_wasm_bindgen::to_value(&sign_request0).unwrap();
    let signature_js0 = bls_sign(sign_request_js0).await.unwrap();
    let signature0 = serde_wasm_bindgen::from_value::<Signature>(signature_js0).unwrap();

    // derive credential
    let dpk_bytes0 = serde_wasm_bindgen::from_value::<BlsKeyPair>(key_pair_js0.clone())
        .unwrap()
        .publicKey
        .unwrap();
    let dpk0 = DeterministicPublicKey::from(array_ref![dpk_bytes0, 0, G2_COMPRESSED_SIZE]);
    let revealed0 = vec![0, 1, 2, 3];
    let eq0 = vec![(0, 2), (0, 3)]; // equivalence class with inconsistency; Message[0,2] != Message[0,3]
    let derive_proof_request = BlsCreateProofMultiRequest {
        signature: vec![signature0],
        publicKey: vec![dpk0],
        messages: vec![messages0],
        revealed: vec![revealed0.clone()],
        nonce: vec![0],
        equivs: vec![eq0],
    };
    let derive_proof_request_js = serde_wasm_bindgen::to_value(&derive_proof_request).unwrap();
    let derived_proofs_js = bls_create_proof_multi(derive_proof_request_js).await;
    assert!(derived_proofs_js.is_ok(), "{:?}", derived_proofs_js);
    let derived_proofs = serde_wasm_bindgen::from_value::<Vec<PoKOfSignatureProofMultiWrapper>>(
        derived_proofs_js.unwrap(),
    )
    .unwrap();
    assert_eq!(derived_proofs.len(), 1);

    // verify derived proof
    let revealed_messages0 = vec![
        b"Message[0,0]".to_vec(), // revealed
        b"Message[0,1]".to_vec(), // revealed
        b"___DUMMY____".to_vec(), // hidden with proof of equality; was "Message[0,2]"
        b"___DUMMY____".to_vec(), // hidden with proof of equality; was "Message[0,3]"
                                  // hidden;                        was "Message[0,4]"
    ];
    let eqv0 = vec![(0, 2), (0, 3)]; // equivalence class corresponding to two different "Message[0,2]" and "Message[0,3]" incorrectly
    let verify_proof_request = BlsVerifyProofMultiContext {
        proof: derived_proofs,
        publicKey: vec![dpk0],
        messages: vec![revealed_messages0],
        revealed: vec![revealed0],
        nonce: vec![0],
        equivs: vec![eqv0],
    };
    let verify_proof_request_js = serde_wasm_bindgen::to_value(&verify_proof_request).unwrap();
    let verify_proof_result_js = bls_verify_proof_multi(verify_proof_request_js)
        .await
        .unwrap();
    let verify_proof_result =
        serde_wasm_bindgen::from_value::<BbsVerifyResponse>(verify_proof_result_js).unwrap();
    assert!(!verify_proof_result.verified);
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub async fn bls_single_redundant_index_test() {
    // issue credential
    let key_pair_js0 = bls_generate_g2_key(None).await.unwrap();
    let messages0 = vec![
        b"Message[0,0]".to_vec(),
        b"Message[0,1]".to_vec(),
        b"Message[0,2]".to_vec(),
        b"Message[0,3]".to_vec(),
        b"Message[0,4]".to_vec(),
    ];
    let sign_request0 = BlsBbsSignRequest {
        keyPair: serde_wasm_bindgen::from_value::<BlsKeyPair>(key_pair_js0.clone()).unwrap(),
        messages: messages0.clone(),
    };
    let sign_request_js0 = serde_wasm_bindgen::to_value(&sign_request0).unwrap();
    let signature_js0 = bls_sign(sign_request_js0).await.unwrap();
    let signature0 = serde_wasm_bindgen::from_value::<Signature>(signature_js0).unwrap();

    // derive credential
    let dpk_bytes0 = serde_wasm_bindgen::from_value::<BlsKeyPair>(key_pair_js0.clone())
        .unwrap()
        .publicKey
        .unwrap();
    let dpk0 = DeterministicPublicKey::from(array_ref![dpk_bytes0, 0, G2_COMPRESSED_SIZE]);
    let revealed0 = vec![4, 0, 3, 3, 3]; // revealed indicies are regarded as set; reordering and duplicating should have no impact
    let derive_proof_request = BlsCreateProofMultiRequest {
        signature: vec![signature0],
        publicKey: vec![dpk0],
        messages: vec![messages0],
        revealed: vec![revealed0.clone()],
        nonce: vec![0],
        equivs: vec![],
    };
    let derive_proof_request_js = serde_wasm_bindgen::to_value(&derive_proof_request).unwrap();
    let derived_proofs_js = bls_create_proof_multi(derive_proof_request_js).await;
    assert!(derived_proofs_js.is_ok(), "{:?}", derived_proofs_js);
    let derived_proofs = serde_wasm_bindgen::from_value::<Vec<PoKOfSignatureProofMultiWrapper>>(
        derived_proofs_js.unwrap(),
    )
    .unwrap();
    assert_eq!(derived_proofs.len(), 1);

    // verify derived proof
    let revealed_messages0 = vec![
        b"Message[0,0]".to_vec(), // revealed
        // hidden
        // hidden
        b"Message[0,3]".to_vec(), // revealed
        b"Message[0,4]".to_vec(), // revealed
    ];
    let verify_proof_request = BlsVerifyProofMultiContext {
        proof: derived_proofs,
        publicKey: vec![dpk0],
        messages: vec![revealed_messages0],
        revealed: vec![revealed0],
        nonce: vec![0],
        equivs: vec![],
    };
    let verify_proof_request_js = serde_wasm_bindgen::to_value(&verify_proof_request).unwrap();
    let verify_proof_result_js = bls_verify_proof_multi(verify_proof_request_js)
        .await
        .unwrap();
    let verify_proof_result =
        serde_wasm_bindgen::from_value::<BbsVerifyResponse>(verify_proof_result_js).unwrap();
    assert!(
        verify_proof_result.verified,
        "{:?}",
        verify_proof_result.error
    );
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub async fn bls_single_out_of_revealed_index_test() {
    // issue credential
    let key_pair_js0 = bls_generate_g2_key(None).await.unwrap();
    let messages0 = vec![b"Message[0,0]".to_vec(), b"Message[0,1]".to_vec()];
    let sign_request0 = BlsBbsSignRequest {
        keyPair: serde_wasm_bindgen::from_value::<BlsKeyPair>(key_pair_js0.clone()).unwrap(),
        messages: messages0.clone(),
    };
    let sign_request_js0 = serde_wasm_bindgen::to_value(&sign_request0).unwrap();
    let signature_js0 = bls_sign(sign_request_js0).await.unwrap();
    let signature0 = serde_wasm_bindgen::from_value::<Signature>(signature_js0).unwrap();

    // derive credential
    let dpk_bytes0 = serde_wasm_bindgen::from_value::<BlsKeyPair>(key_pair_js0.clone())
        .unwrap()
        .publicKey
        .unwrap();
    let dpk0 = DeterministicPublicKey::from(array_ref![dpk_bytes0, 0, G2_COMPRESSED_SIZE]);
    let revealed0 = vec![0, 1, 100]; // invalid index 100
    let derive_proof_request = BlsCreateProofMultiRequest {
        signature: vec![signature0],
        publicKey: vec![dpk0],
        messages: vec![messages0],
        revealed: vec![revealed0],
        nonce: vec![0],
        equivs: vec![],
    };
    let derive_proof_request_js = serde_wasm_bindgen::to_value(&derive_proof_request).unwrap();
    let derived_proofs_js = bls_create_proof_multi(derive_proof_request_js).await;
    assert!(derived_proofs_js.is_err());
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub async fn bls_single_meaningless_equivs_test() {
    // issue credential
    let key_pair_js0 = bls_generate_g2_key(None).await.unwrap();
    let messages0 = vec![b"Message[0,0]".to_vec(), b"Message[0,1]".to_vec()];
    let sign_request0 = BlsBbsSignRequest {
        keyPair: serde_wasm_bindgen::from_value::<BlsKeyPair>(key_pair_js0.clone()).unwrap(),
        messages: messages0.clone(),
    };
    let sign_request_js0 = serde_wasm_bindgen::to_value(&sign_request0).unwrap();
    let signature_js0 = bls_sign(sign_request_js0).await.unwrap();
    let signature0 = serde_wasm_bindgen::from_value::<Signature>(signature_js0).unwrap();

    // derive credential
    let dpk_bytes0 = serde_wasm_bindgen::from_value::<BlsKeyPair>(key_pair_js0.clone())
        .unwrap()
        .publicKey
        .unwrap();
    let dpk0 = DeterministicPublicKey::from(array_ref![dpk_bytes0, 0, G2_COMPRESSED_SIZE]);
    let revealed0 = vec![0, 1];
    let eq0 = vec![(0, 0)]; // equivalence class with only one element (meaningless)
    let derive_proof_request = BlsCreateProofMultiRequest {
        signature: vec![signature0],
        publicKey: vec![dpk0],
        messages: vec![messages0],
        revealed: vec![revealed0.clone()],
        nonce: vec![0],
        equivs: vec![eq0],
    };
    let derive_proof_request_js = serde_wasm_bindgen::to_value(&derive_proof_request).unwrap();
    let derived_proofs_js = bls_create_proof_multi(derive_proof_request_js).await;
    assert!(derived_proofs_js.is_ok(), "{:?}", derived_proofs_js);
    let derived_proofs = serde_wasm_bindgen::from_value::<Vec<PoKOfSignatureProofMultiWrapper>>(
        derived_proofs_js.unwrap(),
    )
    .unwrap();
    assert_eq!(derived_proofs.len(), 1);

    // verify derived proof
    let revealed_messages0 = vec![
        b"Message[0,0]".to_vec(), // revealed
        b"Message[0,1]".to_vec(), // revealed
    ];
    let eqv0 = vec![(0, 0)]; // equivalence class with only one element (meaningless)
    let verify_proof_request = BlsVerifyProofMultiContext {
        proof: derived_proofs,
        publicKey: vec![dpk0],
        messages: vec![revealed_messages0],
        revealed: vec![revealed0],
        nonce: vec![0],
        equivs: vec![eqv0],
    };
    let verify_proof_request_js = serde_wasm_bindgen::to_value(&verify_proof_request).unwrap();
    let verify_proof_result_js = bls_verify_proof_multi(verify_proof_request_js)
        .await
        .unwrap();
    let verify_proof_result =
        serde_wasm_bindgen::from_value::<BbsVerifyResponse>(verify_proof_result_js).unwrap();
    assert!(
        verify_proof_result.verified,
        "{:?}",
        verify_proof_result.error
    );
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub async fn bls_single_invalid_equivs_test() {
    // issue credential
    let key_pair_js0 = bls_generate_g2_key(None).await.unwrap();
    let messages0 = vec![b"Message[0,0]".to_vec(), b"Message[0,1]".to_vec()];
    let sign_request0 = BlsBbsSignRequest {
        keyPair: serde_wasm_bindgen::from_value::<BlsKeyPair>(key_pair_js0.clone()).unwrap(),
        messages: messages0.clone(),
    };
    let sign_request_js0 = serde_wasm_bindgen::to_value(&sign_request0).unwrap();
    let signature_js0 = bls_sign(sign_request_js0).await.unwrap();
    let signature0 = serde_wasm_bindgen::from_value::<Signature>(signature_js0).unwrap();

    // derive credential
    let dpk_bytes0 = serde_wasm_bindgen::from_value::<BlsKeyPair>(key_pair_js0.clone())
        .unwrap()
        .publicKey
        .unwrap();
    let dpk0 = DeterministicPublicKey::from(array_ref![dpk_bytes0, 0, G2_COMPRESSED_SIZE]);
    let revealed0 = vec![0, 1]; // all revealed
    let derive_proof_request = BlsCreateProofMultiRequest {
        signature: vec![signature0],
        publicKey: vec![dpk0],
        messages: vec![messages0],
        revealed: vec![revealed0.clone()],
        nonce: vec![0],
        equivs: vec![], // no equivalence class is given
    };
    let derive_proof_request_js = serde_wasm_bindgen::to_value(&derive_proof_request).unwrap();
    let derived_proofs_js = bls_create_proof_multi(derive_proof_request_js).await;
    assert!(derived_proofs_js.is_ok(), "{:?}", derived_proofs_js);
    let derived_proofs = serde_wasm_bindgen::from_value::<Vec<PoKOfSignatureProofMultiWrapper>>(
        derived_proofs_js.unwrap(),
    )
    .unwrap();
    assert_eq!(derived_proofs.len(), 1);

    // verify derived proof
    let revealed_messages0 = vec![
        b"Message[0,0]".to_vec(), // revealed
        b"Message[0,1]".to_vec(), // revealed
    ];
    let eqv0 = vec![(0, 0)]; // inconsistent equivalence class that is not given during deriveProof
    let verify_proof_request = BlsVerifyProofMultiContext {
        proof: derived_proofs,
        publicKey: vec![dpk0],
        messages: vec![revealed_messages0],
        revealed: vec![revealed0],
        nonce: vec![0],
        equivs: vec![eqv0], // inconsistent equivalence class
    };
    let verify_proof_request_js = serde_wasm_bindgen::to_value(&verify_proof_request).unwrap();
    let verify_proof_result_js = bls_verify_proof_multi(verify_proof_request_js)
        .await
        .unwrap();
    let verify_proof_result =
        serde_wasm_bindgen::from_value::<BbsVerifyResponse>(verify_proof_result_js).unwrap();
    assert!(
        !verify_proof_result.verified,
        "{:?}",
        verify_proof_result.error
    );
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub async fn bls_single_verify_empty_proof_test() {
    // verify empty derived proof
    let eqv0 = vec![];
    let verify_proof_request = BlsVerifyProofMultiContext {
        proof: vec![],
        publicKey: vec![],
        messages: vec![],
        revealed: vec![],
        nonce: vec![0],
        equivs: vec![eqv0],
    };
    let verify_proof_request_js = serde_wasm_bindgen::to_value(&verify_proof_request).unwrap();
    let verify_proof_result_js = bls_verify_proof_multi(verify_proof_request_js)
        .await
        .unwrap();
    let verify_proof_result =
        serde_wasm_bindgen::from_value::<BbsVerifyResponse>(verify_proof_result_js).unwrap();
    assert!(!verify_proof_result.verified);
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub async fn bls_multi_whole_success_test() {
    // issue credential [0]
    let key_pair_js0 = bls_generate_g2_key(None).await.unwrap();
    let messages0 = vec![
        b"Message[0,0]".to_vec(),
        b"Message[0,1]".to_vec(),
        b"Message_EQ_0".to_vec(),
        b"Message_EQ_1".to_vec(),
        b"Message[0,4]".to_vec(),
    ];
    let sign_request0 = BlsBbsSignRequest {
        keyPair: serde_wasm_bindgen::from_value::<BlsKeyPair>(key_pair_js0.clone()).unwrap(),
        messages: messages0.clone(),
    };
    let sign_request_js0 = serde_wasm_bindgen::to_value(&sign_request0).unwrap();
    let signature_js0 = bls_sign(sign_request_js0).await.unwrap();
    let signature0 = serde_wasm_bindgen::from_value::<Signature>(signature_js0).unwrap();

    // verify credential [0]
    let dpk_bytes0 = serde_wasm_bindgen::from_value::<BlsKeyPair>(key_pair_js0.clone())
        .unwrap()
        .publicKey
        .unwrap();
    let dpk0 = DeterministicPublicKey::from(array_ref![dpk_bytes0, 0, G2_COMPRESSED_SIZE]);
    let verify_request0 = BlsBbsVerifyRequest {
        publicKey: dpk0,
        signature: signature0.clone(),
        messages: messages0.clone(),
    };
    let verify_request_js0 = serde_wasm_bindgen::to_value(&verify_request0).unwrap();
    let verify_result_js0 = bls_verify(verify_request_js0).await.unwrap();
    let verify_result0 =
        serde_wasm_bindgen::from_value::<BbsVerifyResponse>(verify_result_js0).unwrap();
    assert!(verify_result0.verified);

    // issue credential [1]
    let key_pair_js1 = bls_generate_g2_key(None).await.unwrap();
    let messages1 = vec![
        b"Message[1,0]".to_vec(),
        b"Message_EQ_1".to_vec(),
        b"Message[1,2]".to_vec(),
        b"Message_EQ_0".to_vec(),
        b"Message[1,4]".to_vec(),
    ];
    let sign_request1 = BlsBbsSignRequest {
        keyPair: serde_wasm_bindgen::from_value::<BlsKeyPair>(key_pair_js1.clone()).unwrap(),
        messages: messages1.clone(),
    };
    let sign_request_js1 = serde_wasm_bindgen::to_value(&sign_request1).unwrap();
    let signature_js1 = bls_sign(sign_request_js1).await.unwrap();
    let signature1 = serde_wasm_bindgen::from_value::<Signature>(signature_js1).unwrap();

    // verify credential [1]
    let dpk_bytes1 = serde_wasm_bindgen::from_value::<BlsKeyPair>(key_pair_js1.clone())
        .unwrap()
        .publicKey
        .unwrap();
    let dpk1 = DeterministicPublicKey::from(array_ref![dpk_bytes1, 0, G2_COMPRESSED_SIZE]);
    let verify_request1 = BlsBbsVerifyRequest {
        publicKey: dpk1,
        signature: signature1.clone(),
        messages: messages1.clone(),
    };
    let verify_request_js1 = serde_wasm_bindgen::to_value(&verify_request1).unwrap();
    let verify_result_js1 = bls_verify(verify_request_js1).await.unwrap();
    let verify_result1 =
        serde_wasm_bindgen::from_value::<BbsVerifyResponse>(verify_result_js1).unwrap();
    assert!(verify_result1.verified);

    // derive credential
    let revealed0 = vec![0, 1, 2, 3]; // messages0 will be revealed except for index 4
    let revealed1 = vec![0, 1, 2, 3]; // messages1 will be revealed except for index 4
    let eq0 = vec![(0, 2), (1, 3)]; // equivalence class corresponding to "Message_EQ_0"
    let eq1 = vec![(0, 3), (1, 1)]; // equivalence class corresponding to "Message_EQ_1"
    let derive_proof_request = BlsCreateProofMultiRequest {
        signature: vec![signature0, signature1],
        publicKey: vec![dpk0, dpk1],
        messages: vec![messages0, messages1],
        revealed: vec![revealed0.clone(), revealed1.clone()],
        nonce: vec![0],
        equivs: vec![eq0, eq1],
    };
    let derive_proof_request_js = serde_wasm_bindgen::to_value(&derive_proof_request).unwrap();
    let derived_proofs_js = bls_create_proof_multi(derive_proof_request_js).await;
    assert!(derived_proofs_js.is_ok(), "{:?}", derived_proofs_js);
    let derived_proofs = serde_wasm_bindgen::from_value::<Vec<PoKOfSignatureProofMultiWrapper>>(
        derived_proofs_js.unwrap(),
    )
    .unwrap();
    assert_eq!(derived_proofs.len(), 2);

    // verify derived proofs
    let revealed_messages0 = vec![
        b"Message[0,0]".to_vec(), // revealed
        b"Message[0,1]".to_vec(), // revealed
        b"___DUMMY____".to_vec(), // hidden with proof of equality; was "Message_EQ_0"
        b"___DUMMY____".to_vec(), // hidden with proof of equality; was "Message_EQ_1"
                                  // hidden;                        was "Message[0,4]"
    ];
    let revealed_messages1 = vec![
        b"Message[1,0]".to_vec(), // revealed
        b"___DUMMY____".to_vec(), // hidden with proof of eqaulity; was "Message_EQ_1"
        b"Message[1,2]".to_vec(), // revealed
        b"___DUMMY____".to_vec(), // hidden with proof of equality; was "Message_EQ_0"
                                  // hidden;                        was "Message[1,4]"
    ];
    let eqv0 = vec![(0, 2), (1, 3)]; // equivalence class corresponding to "Message_EQ_0"
    let eqv1 = vec![(0, 3), (1, 1)]; // equivalence class corresponding to "Message_EQ_1"
    let verify_proof_request = BlsVerifyProofMultiContext {
        proof: derived_proofs,
        publicKey: vec![dpk0, dpk1],
        messages: vec![revealed_messages0, revealed_messages1],
        revealed: vec![revealed0, revealed1],
        nonce: vec![0],
        equivs: vec![eqv0, eqv1],
    };
    let verify_proof_request_js = serde_wasm_bindgen::to_value(&verify_proof_request).unwrap();
    let verify_proof_result_js = bls_verify_proof_multi(verify_proof_request_js)
        .await
        .unwrap();
    let verify_proof_result =
        serde_wasm_bindgen::from_value::<BbsVerifyResponse>(verify_proof_result_js).unwrap();
    assert!(
        verify_proof_result.verified,
        "{:?}",
        verify_proof_result.error
    );
}
