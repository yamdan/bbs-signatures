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

use arrayref::array_ref;
use bbs::{prelude::*, signature::BlindSignature};
use std::convert::TryInto;
use wasm::{prelude::*, BbsVerifyResponse, U8_STRING};
use wasm_bindgen_test::*;

fn string_to_typed_bytes(message: &str) -> Vec<u8> {
    let mut bytes = vec![U8_STRING];
    bytes.extend(message.as_bytes());
    bytes
}

wasm_bindgen_test_configure!(run_in_browser);

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub async fn bounded_bls_signature_request_tests() {
    let key_pair_js0 = bls_generate_g2_key(None).await.unwrap();
    let dpk_bytes0 = serde_wasm_bindgen::from_value::<BlsKeyPair>(key_pair_js0.clone())
        .unwrap()
        .publicKey
        .unwrap();
    let dpk0 = DeterministicPublicKey::from(array_ref![dpk_bytes0, 0, G2_COMPRESSED_SIZE]);

    let request = BoundedBlsSignatureRequestContextRequest {
        signerPublicKey: dpk0,
        proverSecretKey: string_to_typed_bytes("WALLET_MASTER_SECRET"),
        messageCount: 10,
        nonce: b"dummy nonce".to_vec(),
    };
    let js_value = serde_wasm_bindgen::to_value(&request).unwrap();
    let result = bounded_bls_signature_request(js_value).await;
    assert!(result.is_ok());
    let result: BoundedBlsSignatureRequestContextResponse = result.unwrap().try_into().unwrap();

    let request = BoundedBlsSignatureVerifyContextRequest {
        commitment: result.commitment.clone(),
        proofOfHiddenMessages: result.proofOfHiddenMessages.clone(),
        challengeHash: result.challengeHash.clone(),
        messageCount: 10,
        publicKey: dpk0,
        nonce: b"dummy nonce".to_vec(),
    };
    let js_value = serde_wasm_bindgen::to_value(&request).unwrap();
    let res = verify_bounded_bls_signature_request(js_value).await;
    assert!(res.is_ok());
    let res: BbsVerifyResponse = serde_wasm_bindgen::from_value(res.unwrap()).unwrap();
    assert!(res.verified);

    let request = BoundedBlsSignatureVerifyContextRequest {
        commitment: result.commitment.clone(),
        proofOfHiddenMessages: result.proofOfHiddenMessages.clone(),
        challengeHash: result.challengeHash.clone(),
        messageCount: 10,
        publicKey: dpk0,
        nonce: b"bad nonce".to_vec(),
    };
    let js_value = serde_wasm_bindgen::to_value(&request).unwrap();
    let res = verify_bounded_bls_signature_request(js_value).await;
    assert!(res.is_ok());
    let res: BbsVerifyResponse = serde_wasm_bindgen::from_value(res.unwrap()).unwrap();
    assert!(!res.verified);
}

#[allow(non_snake_case)]
#[wasm_bindgen_test]
pub async fn bounded_bls_sign_tests() {
    let key_pair_js0 = bls_generate_g2_key(Some(vec![0u8; 16])).await.unwrap();
    let dpk_bytes0 = serde_wasm_bindgen::from_value::<BlsKeyPair>(key_pair_js0.clone())
        .unwrap()
        .publicKey
        .unwrap();
    let dpk0 = DeterministicPublicKey::from(array_ref![dpk_bytes0, 0, G2_COMPRESSED_SIZE]);
    let request = BoundedBlsSignatureRequestContextRequest {
        signerPublicKey: dpk0,
        proverSecretKey: string_to_typed_bytes("WALLET_MASTER_SECRET"),
        messageCount: 3,
        nonce: b"dummy nonce".to_vec(),
    };
    let js_value = serde_wasm_bindgen::to_value(&request).unwrap();
    let result = bounded_bls_signature_request(js_value).await;
    assert!(result.is_ok());
    let result: BoundedBlsSignatureRequestContextResponse = result.unwrap().try_into().unwrap();
    let blindingFactor = result.blindingFactor;

    // blind sign
    let messages = vec![
        string_to_typed_bytes("Message1"),
        string_to_typed_bytes("Message2"),
        string_to_typed_bytes("Message3"),
    ];
    let request = BoundedBlsSignContextRequest {
        keyPair: serde_wasm_bindgen::from_value::<BlsKeyPair>(key_pair_js0.clone()).unwrap(),
        messages: messages.clone(),
        commitment: result.commitment.clone(),
    };
    let js_value = serde_wasm_bindgen::to_value(&request).unwrap();
    let result = bounded_bls_sign(js_value).await;
    assert!(result.is_ok());
    let result: BlindSignature = result.unwrap().try_into().unwrap();

    // unblind
    let request = UnblindBoundedSignatureRequest {
        signature: result,
        blindingFactor,
    };
    let js_value = serde_wasm_bindgen::to_value(&request).unwrap();
    let result = unblind_bounded_bls_signature(js_value).await;
    assert!(result.is_ok());
}
