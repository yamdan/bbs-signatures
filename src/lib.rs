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

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[macro_use]
extern crate arrayref;

use bbs::prelude::*;
use ff_zeroize::{PrimeField, PrimeFieldDecodingError};
use pairing_plus::bls12_381::{Fr, FrRepr};
use serde::{
    de::{Error as DError, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{
    array::TryFromSliceError,
    collections::BTreeSet,
    convert::{TryFrom, TryInto},
    error, fmt,
};
use wasm_bindgen::prelude::*;

const U8_STRING: u8 = 0u8;
const U8_INTEGER: u8 = 1u8;

#[macro_use]
mod macros;
pub mod bbs_plus;
pub mod bls12381;
mod utils;

wasm_impl!(BbsVerifyResponse, verified: bool, error: Option<String>);

#[derive(Debug)]
pub struct PoKOfSignatureProofWrapper {
    pub bit_vector: Vec<u8>,
    pub proof: PoKOfSignatureProof,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PoKOfSignatureProofMultiWrapper {
    pub message_count: usize,
    pub proof: PoKOfSignatureProof,
    pub range_commitment_proofs: Vec<PoKOfCommitmentProof>,
}

impl PoKOfSignatureProofWrapper {
    pub fn new(
        message_count: usize,
        revealed: &BTreeSet<usize>,
        proof: PoKOfSignatureProof,
    ) -> Self {
        let mut bit_vector = (message_count as u16).to_be_bytes().to_vec();
        bit_vector.append(&mut revealed_to_bitvector(message_count, revealed));
        Self { bit_vector, proof }
    }

    pub fn unwrap(self) -> (BTreeSet<usize>, PoKOfSignatureProof) {
        (bitvector_to_revealed(&self.bit_vector[2..]), self.proof)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = self.bit_vector.to_vec();
        data.append(&mut self.proof.to_bytes_compressed_form());
        data
    }
}

impl TryFrom<&[u8]> for PoKOfSignatureProofWrapper {
    type Error = JsValue;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let message_count = u16::from_be_bytes(*array_ref![value, 0, 2]) as usize;
        let bitvector_length = (message_count / 8) + 1;
        let offset = bitvector_length + 2;
        if offset > value.len() {
            return Err(JsValue::FALSE);
        }
        let proof = map_err!(PoKOfSignatureProof::try_from(&value[offset..]))?;
        Ok(Self {
            bit_vector: value[..offset].to_vec(),
            proof,
        })
    }
}

impl Serialize for PoKOfSignatureProofWrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes().as_slice())
    }
}

impl<'a> Deserialize<'a> for PoKOfSignatureProofWrapper {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        struct DeserializeVisitor;

        impl<'a> Visitor<'a> for DeserializeVisitor {
            type Value = PoKOfSignatureProofWrapper;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("expected byte array")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<PoKOfSignatureProofWrapper, E>
            where
                E: DError,
            {
                PoKOfSignatureProofWrapper::try_from(value)
                    .map_err(|_| DError::invalid_value(serde::de::Unexpected::Bytes(value), &self))
            }
        }

        deserializer.deserialize_bytes(DeserializeVisitor)
    }
}

impl PoKOfSignatureProofMultiWrapper {
    pub fn new(
        message_count: usize,
        proof: PoKOfSignatureProof,
        range_commitment_proofs: Vec<PoKOfCommitmentProof>,
    ) -> Self {
        Self {
            message_count,
            proof,
            range_commitment_proofs,
        }
    }
}

pub mod prelude {
    pub use crate::bbs_plus::*;
    pub use crate::bls12381::*;
}

/// Expects `revealed` to be sorted
pub(crate) fn revealed_to_bitvector(total: usize, revealed: &BTreeSet<usize>) -> Vec<u8> {
    let mut bytes = vec![0u8; (total / 8) + 1];

    for r in revealed {
        let idx = *r / 8;
        let bit = (*r % 8) as u8;
        bytes[idx] |= 1u8 << bit;
    }

    // Convert to big endian
    bytes.reverse();
    bytes
}

/// Convert big-endian vector to u32
pub(crate) fn bitvector_to_revealed(data: &[u8]) -> BTreeSet<usize> {
    let mut revealed_messages = BTreeSet::new();
    let mut scalar = 0;

    for b in data.iter().rev() {
        let mut v = *b;
        let mut remaining = 8;
        while v > 0 {
            let revealed = v & 1u8;
            if revealed == 1 {
                revealed_messages.insert(scalar);
            }
            v >>= 1;
            scalar += 1;
            remaining -= 1;
        }
        scalar += remaining;
    }
    revealed_messages
}

#[derive(Debug, Clone)]
enum GenSignatureMessageError {
    EmptyMessage,
    InvalidBitLength,
    InvalidMessageType,
    TryFromSliceError,
    PrimeFieldDecodingError,
}

impl fmt::Display for GenSignatureMessageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SignatureMessage generation error")
    }
}

impl error::Error for GenSignatureMessageError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

impl From<TryFromSliceError> for GenSignatureMessageError {
    fn from(_err: TryFromSliceError) -> GenSignatureMessageError {
        GenSignatureMessageError::TryFromSliceError
    }
}

impl From<PrimeFieldDecodingError> for GenSignatureMessageError {
    fn from(_err: PrimeFieldDecodingError) -> GenSignatureMessageError {
        GenSignatureMessageError::PrimeFieldDecodingError
    }
}

impl From<GenSignatureMessageError> for JsValue {
    fn from(_err: GenSignatureMessageError) -> Self {
        JsValue::from_str(&format!("{}", _err))
    }
}

fn gen_signature_message(m: &[u8]) -> Result<SignatureMessage, GenSignatureMessageError> {
    if m.is_empty() {
        return Err(GenSignatureMessageError::EmptyMessage);
    }

    match m[0] {
        U8_STRING => Ok(SignatureMessage::hash(&m[1..])),
        U8_INTEGER => {
            if m.len() != 5 {
                return Err(GenSignatureMessageError::InvalidBitLength);
            };
            let m_64 = [&[0; 4], &m[1..5]].concat(); // pad 0's to make 32-bit integer to 64-bit
            let v = Fr::from_repr(FrRepr::from(u64::from_be_bytes(m_64[..].try_into()?)))?;
            Ok(SignatureMessage::from(v))
        }
        _ => Err(GenSignatureMessageError::InvalidMessageType),
    }
}
