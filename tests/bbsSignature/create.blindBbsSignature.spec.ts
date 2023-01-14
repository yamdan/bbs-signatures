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

import {
  generateBls12381G2KeyPair,
  BlsKeyPair,
  BlindBlsSignatureRequestContextRequest,
  blindBlsSignatureRequest,
  BlindBlsSignatureVerifyContextRequest,
  verifyBlindBlsSignatureRequest,
  BlindBlsSignContextRequest,
  blindBlsSign,
  unblindBlindBlsSignature,
  UnblindBlindSignatureRequest,
  BlsBbsVerifyRequest,
  blsVerify,
} from "../../lib";
import { stringToBytes, stringToTypedBytes } from "../utilities";

describe("blindBbsSignature", () => {
  describe("signature request", () => {
    let blsKeyPair: BlsKeyPair;

    beforeAll(async () => {
      blsKeyPair = await generateBls12381G2KeyPair();
    });

    it("should create and verify a signature request", async () => {
      const request: BlindBlsSignatureRequestContextRequest = {
        signerPublicKey: blsKeyPair.publicKey,
        proverSecretKey: stringToTypedBytes("PROVER_SECRET"),
        messageCount: 10,
        nonce: stringToBytes("0123456789"),
      };
      const response = await blindBlsSignatureRequest(request);
      expect(request).toBeDefined();
      const vRequest: BlindBlsSignatureVerifyContextRequest = {
        commitment: response.commitment,
        proofOfHiddenMessages: response.proofOfHiddenMessages,
        challengeHash: response.challengeHash,
        messageCount: 10,
        publicKey: blsKeyPair.publicKey,
        nonce: stringToBytes("0123456789"),
      };
      const vResponse = await verifyBlindBlsSignatureRequest(vRequest);
      expect(vResponse.verified).toBeTruthy();
    });
  });

  describe("sign and verify", () => {
    let blsKeyPair: BlsKeyPair;
    let commitment: Uint8Array;
    let blindingFactor: Uint8Array;

    beforeAll(async () => {
      blsKeyPair = await generateBls12381G2KeyPair();
      const request: BlindBlsSignatureRequestContextRequest = {
        signerPublicKey: blsKeyPair.publicKey,
        proverSecretKey: stringToTypedBytes("PROVER_SECRET"),
        messageCount: 3,
        nonce: stringToBytes("0123456789"),
      };
      const response = await blindBlsSignatureRequest(request);
      commitment = response.commitment;
      blindingFactor = response.blindingFactor;
    });

    it("should sign and verify a blind signature", async () => {
      // blind sign
      const sRequest: BlindBlsSignContextRequest = {
        keyPair: blsKeyPair,
        messages: [
          stringToTypedBytes("ExampleMessage"),
          stringToTypedBytes("ExampleMessage2"),
          stringToTypedBytes("ExampleMessage3"),
        ],
        commitment: commitment,
      };
      const sResponse = await blindBlsSign(sRequest);
      expect(sResponse).toBeDefined();

      // unblind
      const uRequest: UnblindBlindSignatureRequest = {
        signature: sResponse,
        blindingFactor: blindingFactor,
      };
      const uResponse = await unblindBlindBlsSignature(uRequest);
      expect(uResponse).toBeDefined();

      // verify bound signature
      const verifyRequest: BlsBbsVerifyRequest = {
        publicKey: blsKeyPair.publicKey,
        messages: [
          stringToTypedBytes("ExampleMessage"),
          stringToTypedBytes("ExampleMessage2"),
          stringToTypedBytes("ExampleMessage3"),
          stringToTypedBytes("PROVER_SECRET"),
        ],
        signature: uResponse,
      };
      expect((await blsVerify(verifyRequest)).verified).toBeTruthy();
    });

    it("should not verify a invalid message", async () => {
      // blind sign
      const sRequest: BlindBlsSignContextRequest = {
        keyPair: blsKeyPair,
        messages: [
          stringToTypedBytes("ExampleMessage"),
          stringToTypedBytes("ExampleMessage2"),
          stringToTypedBytes("ExampleMessage3"),
        ],
        commitment: commitment,
      };
      const sResponse = await blindBlsSign(sRequest);
      expect(sResponse).toBeDefined();

      // unblind
      const uRequest: UnblindBlindSignatureRequest = {
        signature: sResponse,
        blindingFactor: blindingFactor,
      };
      const uResponse = await unblindBlindBlsSignature(uRequest);
      expect(uResponse).toBeDefined();

      // verify bound signature
      const verifyRequest: BlsBbsVerifyRequest = {
        publicKey: blsKeyPair.publicKey,
        messages: [
          stringToTypedBytes("BadMessage"),
          stringToTypedBytes("ExampleMessage2"),
          stringToTypedBytes("ExampleMessage3"),
          stringToTypedBytes("PROVER_SECRET"),
        ],
        signature: uResponse,
      };
      expect((await blsVerify(verifyRequest)).verified).toBeFalsy();
    });
  });
});
