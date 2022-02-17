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

use amcl_wrapper::group_elem_g1::{G1Vector as AMCLG1Vector, G1 as AMCLG1};
use amcl_wrapper::{
    field_elem::FieldElement,
    group_elem::GroupElement,
    ECCurve::{big::BIG, ecp::ECP},
};
use bbs::prelude::*;
use bulletproofs_amcl::{
    r1cs::{
        gadgets::bound_check::{gen_proof_of_bounded_num, verify_proof_of_bounded_num},
        R1CSProof,
    },
    utils::get_generators,
};
use ff_zeroize::{PrimeField, PrimeFieldDecodingError};
use pairing_plus::{
    bls12_381::{Fq, FqRepr, Fr, FrRepr, G1},
    CurveAffine, CurveProjective,
};
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
    pub bulletproofs: Vec<(R1CSProof, Vec<AMCLG1>)>,
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
        bulletproofs: Vec<(R1CSProof, Vec<AMCLG1>)>,
    ) -> Self {
        Self {
            message_count,
            proof,
            range_commitment_proofs,
            bulletproofs,
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

#[derive(Debug, Clone)]
enum GenRangeProofError {
    ValOverflow,
    InvalidProof,
    InvalidCommitment,
}

impl fmt::Display for GenRangeProofError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                GenRangeProofError::ValOverflow => "val should be integer between 0 and 2^32",
                GenRangeProofError::InvalidProof => "invalid proof",
                GenRangeProofError::InvalidCommitment => "invalid commitment",
            }
        )
    }
}

#[derive(Debug, Clone)]
enum VerifyRangeProofError {
    VerificationError,
    InvalidCommitment,
}

impl fmt::Display for VerifyRangeProofError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                VerifyRangeProofError::VerificationError => "verification error of bulletproofs",
                VerifyRangeProofError::InvalidCommitment => "invalid commitment",
            }
        )
    }
}

fn gen_rangeproof(
    val: &Fr,
    blinding: &Fr,
    lower: u64,
    upper: u64,
    g: &G1,
    h: &G1,
    c: &G1,
) -> Result<(R1CSProof, Vec<AMCLG1>), GenRangeProofError> {
    // TODO: replace with more appropriate label
    let transcript_label = b"BbsTermwiseSignature2021RangeProof";
    // TODO: should be given as global parameters or issuer-specific public keys
    let G: AMCLG1Vector = get_generators("G", 128).into();
    let H: AMCLG1Vector = get_generators("H", 128).into();

    let max_bits_in_val: usize = (64 - (upper - lower).leading_zeros()).try_into().unwrap();

    let val_repr = val.into_repr();
    let val_ref = val_repr.as_ref();
    if val_ref[1] > 0 || val_ref[2] > 0 || val_ref[3] > 0 {
        return Err(GenRangeProofError::ValOverflow);
    }
    let val = val_ref[0];

    let blinding = pp_fr_to_amcl_fieldelement(blinding);
    let g = pp_g1_to_amcl_g1(g);
    let h = pp_g1_to_amcl_g1(h);

    // given commitment
    let c = pp_g1_to_amcl_g1(c);

    match gen_proof_of_bounded_num(
        val,
        Some(blinding),
        lower,
        upper,
        max_bits_in_val,
        transcript_label,
        &g,
        &h,
        &G,
        &H,
    ) {
        Ok((proof, commitments)) => {
            // check the equality of two commitments generated by bbs+ and bulletproofs
            if c == commitments[0] {
                Ok((proof, commitments))
            } else {
                Err(GenRangeProofError::InvalidCommitment)
            }
        }
        _ => Err(GenRangeProofError::InvalidProof),
    }
}

fn verify_rangeproof(
    proof: R1CSProof,
    commitments: Vec<AMCLG1>,
    lower: u64,
    upper: u64,
    g: &G1,
    h: &G1,
    c: &G1,
) -> Result<(), VerifyRangeProofError> {
    // TODO: replace with more appropriate label
    let transcript_label = b"BbsTermwiseSignature2021RangeProof";
    // TODO: should be given as global parameters or issuer-specific public keys
    let G: AMCLG1Vector = get_generators("G", 128).into();
    let H: AMCLG1Vector = get_generators("H", 128).into();
    
    let max_bits_in_val: usize = (64 - (upper - lower).leading_zeros()).try_into().unwrap();

    let g = pp_g1_to_amcl_g1(g);
    let h = pp_g1_to_amcl_g1(h);

    // given commitment
    let c = pp_g1_to_amcl_g1(c);
    if c != commitments[0] {
        return Err(VerifyRangeProofError::InvalidCommitment);
    }

    match verify_proof_of_bounded_num(
        lower,
        upper,
        max_bits_in_val,
        proof,
        commitments,
        transcript_label,
        &g,
        &h,
        &G,
        &H,
    ) {
        Ok(_) => Ok(()),
        Err(_) => Err(VerifyRangeProofError::VerificationError),
    }
}

pub fn pp_fr_to_amcl_fieldelement(fr: &Fr) -> FieldElement {
    let frrepr: FrRepr = fr.into_repr();
    let u64_array: &[u64] = frrepr.as_ref();
    let mut bytes: [u8; 48] = [0; 48];
    for i in 0..4 {
        let tmp = u64_array[3 - i].to_be_bytes();
        for j in 0..8 {
            bytes[i * 8 + j + 16] = tmp[j];
        }
    }
    FieldElement::from_bytes(&bytes).unwrap()
}

fn pp_fq_to_amcl_big(fq: Fq) -> BIG {
    let pp_fqrepr: FqRepr = FqRepr::from(fq);
    let pp_u64_array: &[u64] = pp_fqrepr.as_ref();
    let mut bytes: [u8; 48] = [0; 48];
    for i in 0..6 {
        let tmp = pp_u64_array[5 - i].to_be_bytes();
        for j in 0..8 {
            bytes[i * 8 + j] = tmp[j];
        }
    }
    BIG::frombytes(&bytes)
}

pub fn pp_g1_to_amcl_ecp(g1: &G1) -> ECP {
    let affine = g1.into_affine();
    let tuple_affine = affine.as_tuple();
    let big_x = pp_fq_to_amcl_big(*tuple_affine.0);
    let big_y = pp_fq_to_amcl_big(*tuple_affine.1);
    ECP::new_bigs(&big_x, &big_y)
}

pub fn pp_g1_to_amcl_g1(g1: &G1) -> AMCLG1 {
    let ecp = pp_g1_to_amcl_ecp(g1);
    let mut bytes: [u8; 97] = [0; 97];
    ecp.tobytes(&mut bytes, false);
    AMCLG1::from_bytes(&bytes).unwrap()
}
