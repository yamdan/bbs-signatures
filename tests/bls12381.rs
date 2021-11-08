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
pub async fn bls_sign_tests() {
    // issue credential1
    let key_pair_js1 = bls_generate_g2_key(None).await.unwrap();
    let messages1 = vec![
        b"Message11".to_vec(),
        b"Message12".to_vec(),
        b"Message**".to_vec(),
    ];
    let sign_request1 = BlsBbsSignRequest {
        keyPair: serde_wasm_bindgen::from_value::<BlsKeyPair>(key_pair_js1.clone()).unwrap(),
        messages: messages1.clone(),
    };
    let sign_request_js1 = serde_wasm_bindgen::to_value(&sign_request1).unwrap();
    let signature_js1 = bls_sign(sign_request_js1).await.unwrap();
    let signature1 = serde_wasm_bindgen::from_value::<Signature>(signature_js1).unwrap();

    // verify credential1
    let dpk_bytes1 = serde_wasm_bindgen::from_value::<BlsKeyPair>(key_pair_js1.clone())
        .unwrap()
        .publicKey
        .unwrap();
    let dpk1 = DeterministicPublicKey::from(array_ref![dpk_bytes1, 0, G2_COMPRESSED_SIZE]);
    let verify_request1 = BlsBbsVerifyRequest {
        publicKey: dpk1,
        signature: signature1,
        messages: messages1.clone(),
    };
    let verify_request_js1 = serde_wasm_bindgen::to_value(&verify_request1).unwrap();
    let verify_result_js1 = bls_verify(verify_request_js1).await.unwrap();
    let verify_result1 =
        serde_wasm_bindgen::from_value::<BbsVerifyResponse>(verify_result_js1).unwrap();
    assert!(verify_result1.verified);

    // issue credential2
    let key_pair_js2 = bls_generate_g2_key(None).await.unwrap();
    let messages2 = vec![
        b"Message21".to_vec(),
        b"Message**".to_vec(),
        b"Message23".to_vec(),
    ];
    let sign_request2 = BlsBbsSignRequest {
        keyPair: serde_wasm_bindgen::from_value::<BlsKeyPair>(key_pair_js2.clone()).unwrap(),
        messages: messages2.clone(),
    };
    let sign_request_js2 = serde_wasm_bindgen::to_value(&sign_request2).unwrap();
    let signature_js2 = bls_sign(sign_request_js2).await.unwrap();
    let signature2 = serde_wasm_bindgen::from_value::<Signature>(signature_js2).unwrap();

    // verify credential2
    let dpk_bytes2 = serde_wasm_bindgen::from_value::<BlsKeyPair>(key_pair_js2.clone())
        .unwrap()
        .publicKey
        .unwrap();
    let dpk2 = DeterministicPublicKey::from(array_ref![dpk_bytes2, 0, G2_COMPRESSED_SIZE]);
    let verify_request2 = BlsBbsVerifyRequest {
        publicKey: dpk2,
        signature: signature2,
        messages: messages2.clone(),
    };
    let verify_request_js2 = serde_wasm_bindgen::to_value(&verify_request2).unwrap();
    let verify_result_js2 = bls_verify(verify_request_js2).await.unwrap();
    let verify_result2 =
        serde_wasm_bindgen::from_value::<BbsVerifyResponse>(verify_result_js2).unwrap();
    assert!(verify_result2.verified);

    // TBD: derive credential
}
