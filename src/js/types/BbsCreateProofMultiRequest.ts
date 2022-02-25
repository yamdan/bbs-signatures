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
 * A request to create a BBS proof from a supplied BBS signature
 */
export interface BbsCreateProofMultiRequest {
  /**
   * BBS signature to generate the BBS proof from
   */
  readonly signature: Uint8Array[];
  /**
   * Public key of the original signer of the signature
   */
  readonly publicKey: Uint8Array[];
  /**
   * The messages that were originally signed
   */
  readonly messages: readonly Uint8Array[][];
  /**
   * The zero based indicies of which messages to reveal
   */
  readonly revealed: readonly number[][];
  /**
   * A nonce for the resulting proof
   */
  readonly nonce: Uint8Array;
  /**
   * The equivalent classes to indicate which attributes are to be proved their equalities
   * e.g., [[[0,3], [0,5], [1,4]], [[0,4], [1,5]]] means:
   *   - attribute 3 and 5 in credential 0 and attribute 4 in credential 1 are proved to be the same
   *   - attribute 4 in credential 0 and attribute 5 in credential 1 are proved to be the same
   */
  readonly equivs: readonly [number, number][][];
  /**
   * The term indicies and ranges for range proofs
   * e.g., [
   *         [ [18, 0, 1000], [22, 0, 1000], [30, 0, 1000], [34, 100000, 150000] ],
   *         [ [18, 1, 5] ]
   *       ] means:
   *   - 18th, 22nd, and 30th attribute in credential 0 are proved to be values between 0 and 1000
   *   - 34th attribute in credential 0 is proved to be a value between 100000 and 150000
   *   - 18th attribute in credential 1 is proved to be a value between 1 and 5
   */
  readonly range: readonly [number, number, number][][];
}
