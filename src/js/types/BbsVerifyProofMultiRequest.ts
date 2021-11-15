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

/**
 * A request to verify a BBS proof
 */
export interface BbsVerifyProofMultiRequest {
  /**
   * The BBS proof to verify
   */
  readonly proof: Uint8Array[];
  /**
   * Public key of the signer of the proof to verify
   */
  readonly publicKey: Uint8Array[];
  /**
   * Revealed messages to verify (TODO maybe rename this field??)
   */
  readonly messages: readonly Uint8Array[][];
  /**
   * The zero based indicies of which messages to reveal (expected to be sorted)
   */
  readonly revealed: readonly number[][];
  /**
   * Nonce included in the proof for the un-revealed attributes (OPTIONAL)
   */
  readonly nonce: Uint8Array;
  /**
   * The equivalent classes to indicate which attributes are to be proved their equalities
   * e.g., [[[0,3], [0,5], [1,4]], [[0,4], [1,5]]] means:
   *   - attribute 3 and 5 in credential 0 and attribute 4 in credential 1 are proved to be the same
   *   - attribute 4 in credential 0 and attribute 5 in credential 1 are proved to be the same
   */
  readonly equivs: readonly [number, number][][];
}
