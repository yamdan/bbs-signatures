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
  BbsCreateProofRequest,
  createProof,
  blsCreateProofMulti,
  BbsCreateProofMultiRequest,
} from "../../lib";
import { randomBytes } from "@stablelib/random";
import { base64Decode, stringToBytes, stringToTypedBytes } from "../utilities";

describe("bbsSignature", () => {
  describe("createProof", () => {
    it("should create proof revealing single message from single message signature", async () => {
      const messages = [stringToTypedBytes("RmtnDBJHso5iSg==")];
      const bbsPublicKey = base64Decode(
        "uI9+d9OZ2Yzl5zMmWltuBvFjUKLs+Q9wiuTtzqZwE3tzfRwmf6aPNoBCOF2Zwyc/B3qhjwStqFDLKyy6xott9WAGTlVwwA4igwJwtXaF6jeHfkwvfbvuI155QPg+pigmgiAr/dcHklf5+4yaPpq7+SBgzUKknTYR6uC7RemOdS058q14/s/UTcyG71pvxyH5AAAAAYNH/5xWsNqf3MSYCTzFgxqrlLM+DaJYu1FP84Hb6KKzcI1RHoux8kDXBVF32StjOg=="
      );
      const signature = base64Decode(
        "iEM5pyItzOv3IwS/6yYB8tvj11D0QdrcHDuPpjUAxdgHsXz05yR3UUdKRLZJKJo2YUHlKfzccE4m7waZyoLEkBLFiK2g54Q2i+CdtYBgDdkUDsoULSBMcH1MwGHwdjfXpldFNFrHFx/IAvLVniyeMQ=="
      );

      const request: BbsCreateProofRequest = {
        signature,
        publicKey: bbsPublicKey,
        messages,
        nonce: stringToBytes("0123456789"),
        revealed: [0],
      };

      const proof = await createProof(request);
      expect(proof).toBeInstanceOf(Uint8Array);
      expect(proof.length).toEqual(383);
    });

    it("should create proof revealing all messages from multi-message signature", async () => {
      const messages = [
        stringToTypedBytes("J42AxhciOVkE9w=="),
        stringToTypedBytes("PNMnARWIHP+s2g=="),
        stringToTypedBytes("ti9WYhhEej85jw=="),
      ];
      const bbsPublicKey = base64Decode(
        "o6kQ4DspDhUa1Cvo2//bpXBv2SlxV1fblNcRB6p+yEos8pVgivndRjUjm1nNs755Eei6/EOE0DUd8Ph1DSV9gDWwyzjj6EkVVgBRHxjMFM1z7yyOorOO2v5+vLMfazrhl6BzhSd+2k4w8mpE3VBFcwT5iszBG1546bTLjpRu7McSbA7+cCAWMxrN8ESvnWEBAAAAA6yRcDzNmw6AgAsBK4qLqRV2fWvRftGyR0j3mHb65G3cCwMLovzjP6XGOYXxr2jJkaiTzJgpIy2JcYluNORAGiHw+IYnce+xjPVW2tZsEsQaeeC+njhcM3oaFuyeQBdEOrIsiEmi0luivUovCfvqRIIC/tMrJDUoRNIk5GpQrTR/Sm9KdZogJw1eaEbiG/dIaQ=="
      );
      const signature = base64Decode(
        "hF4nqu92D5Ur+2YYeRnEFIs6TdSrCFf4blUOU5nmndtqv+3quh5nssksfE/APTSnMKVg9X44OT7IyqxonIH7xLuNJjBkG7KYma9urLMBCo4x5JoTWPaG1p7URXapIpy1ng+avITVXJin9XQoxPxyNA=="
      );

      const request: BbsCreateProofRequest = {
        signature,
        publicKey: bbsPublicKey,
        messages,
        nonce: randomBytes(10),
        revealed: [0, 1, 2],
      };

      const proof = await createProof(request);
      expect(proof).toBeInstanceOf(Uint8Array);
      expect(proof.length).toEqual(383); //TODO add a reason for this and some constants?
    });

    it("should create proof revealing single message from multi-message signature", async () => {
      const messages = [
        stringToTypedBytes("J42AxhciOVkE9w=="),
        stringToTypedBytes("PNMnARWIHP+s2g=="),
        stringToTypedBytes("ti9WYhhEej85jw=="),
      ];
      const bbsPublicKey = base64Decode(
        "o6kQ4DspDhUa1Cvo2//bpXBv2SlxV1fblNcRB6p+yEos8pVgivndRjUjm1nNs755Eei6/EOE0DUd8Ph1DSV9gDWwyzjj6EkVVgBRHxjMFM1z7yyOorOO2v5+vLMfazrhl6BzhSd+2k4w8mpE3VBFcwT5iszBG1546bTLjpRu7McSbA7+cCAWMxrN8ESvnWEBAAAAA6yRcDzNmw6AgAsBK4qLqRV2fWvRftGyR0j3mHb65G3cCwMLovzjP6XGOYXxr2jJkaiTzJgpIy2JcYluNORAGiHw+IYnce+xjPVW2tZsEsQaeeC+njhcM3oaFuyeQBdEOrIsiEmi0luivUovCfvqRIIC/tMrJDUoRNIk5GpQrTR/Sm9KdZogJw1eaEbiG/dIaQ=="
      );
      const signature = base64Decode(
        "hF4nqu92D5Ur+2YYeRnEFIs6TdSrCFf4blUOU5nmndtqv+3quh5nssksfE/APTSnMKVg9X44OT7IyqxonIH7xLuNJjBkG7KYma9urLMBCo4x5JoTWPaG1p7URXapIpy1ng+avITVXJin9XQoxPxyNA=="
      );

      const request: BbsCreateProofRequest = {
        signature,
        publicKey: bbsPublicKey,
        messages,
        nonce: randomBytes(10),
        revealed: [0],
      };

      const proof = await createProof(request);
      expect(proof).toBeInstanceOf(Uint8Array);
      expect(proof.length).toEqual(447); //TODO add a reason for this and some constants?
    });

    it("should create proof revealing multiple messages from multi-message signature", async () => {
      const messages = [
        stringToTypedBytes("J42AxhciOVkE9w=="),
        stringToTypedBytes("PNMnARWIHP+s2g=="),
        stringToTypedBytes("ti9WYhhEej85jw=="),
      ];

      const bbsPublicKey = base64Decode(
        "o6kQ4DspDhUa1Cvo2//bpXBv2SlxV1fblNcRB6p+yEos8pVgivndRjUjm1nNs755Eei6/EOE0DUd8Ph1DSV9gDWwyzjj6EkVVgBRHxjMFM1z7yyOorOO2v5+vLMfazrhl6BzhSd+2k4w8mpE3VBFcwT5iszBG1546bTLjpRu7McSbA7+cCAWMxrN8ESvnWEBAAAAA6yRcDzNmw6AgAsBK4qLqRV2fWvRftGyR0j3mHb65G3cCwMLovzjP6XGOYXxr2jJkaiTzJgpIy2JcYluNORAGiHw+IYnce+xjPVW2tZsEsQaeeC+njhcM3oaFuyeQBdEOrIsiEmi0luivUovCfvqRIIC/tMrJDUoRNIk5GpQrTR/Sm9KdZogJw1eaEbiG/dIaQ=="
      );
      const signature = base64Decode(
        "hF4nqu92D5Ur+2YYeRnEFIs6TdSrCFf4blUOU5nmndtqv+3quh5nssksfE/APTSnMKVg9X44OT7IyqxonIH7xLuNJjBkG7KYma9urLMBCo4x5JoTWPaG1p7URXapIpy1ng+avITVXJin9XQoxPxyNA=="
      );

      const request: BbsCreateProofRequest = {
        signature,
        publicKey: bbsPublicKey,
        messages,
        nonce: randomBytes(10),
        revealed: [0, 2],
      };

      const proof = await createProof(request);
      expect(proof).toBeInstanceOf(Uint8Array);
      expect(proof.length).toEqual(415); //TODO evaluate this length properly add a reason for this and some constants?
    });

    it("should fail to create proof when attempting to create one with an unsigned extra message", async () => {
      const messages = [
        stringToTypedBytes("J42AxhciOVkE9w=="),
        stringToTypedBytes("PNMnARWIHP+s2g=="),
        stringToTypedBytes("ti9WYhhEej85jw=="),
        stringToTypedBytes("badmessagex01a=="),
      ];

      const bbsPublicKey = base64Decode(
        "o6kQ4DspDhUa1Cvo2//bpXBv2SlxV1fblNcRB6p+yEos8pVgivndRjUjm1nNs755Eei6/EOE0DUd8Ph1DSV9gDWwyzjj6EkVVgBRHxjMFM1z7yyOorOO2v5+vLMfazrhl6BzhSd+2k4w8mpE3VBFcwT5iszBG1546bTLjpRu7McSbA7+cCAWMxrN8ESvnWEBAAAAA6yRcDzNmw6AgAsBK4qLqRV2fWvRftGyR0j3mHb65G3cCwMLovzjP6XGOYXxr2jJkaiTzJgpIy2JcYluNORAGiHw+IYnce+xjPVW2tZsEsQaeeC+njhcM3oaFuyeQBdEOrIsiEmi0luivUovCfvqRIIC/tMrJDUoRNIk5GpQrTR/Sm9KdZogJw1eaEbiG/dIaQ=="
      );
      const signature = base64Decode(
        "hF4nqu92D5Ur+2YYeRnEFIs6TdSrCFf4blUOU5nmndtqv+3quh5nssksfE/APTSnMKVg9X44OT7IyqxonIH7xLuNJjBkG7KYma9urLMBCo4x5JoTWPaG1p7URXapIpy1ng+avITVXJin9XQoxPxyNA=="
      );

      const request: BbsCreateProofRequest = {
        signature,
        publicKey: bbsPublicKey,
        messages,
        nonce: randomBytes(10),
        revealed: [0, 1, 2, 3],
      };

      await expect(createProof(request)).rejects.toThrowError(
        "Failed to create proof"
      );
    });

    it("should fail to create proof when attempting to create one with a modified message", async () => {
      const messages = [
        stringToTypedBytes("badmessagex01a=="),
        stringToTypedBytes("PNMnARWIHP+s2g=="),
        stringToTypedBytes("ti9WYhhEej85jw=="),
      ];

      const bbsPublicKey = base64Decode(
        "o6kQ4DspDhUa1Cvo2//bpXBv2SlxV1fblNcRB6p+yEos8pVgivndRjUjm1nNs755Eei6/EOE0DUd8Ph1DSV9gDWwyzjj6EkVVgBRHxjMFM1z7yyOorOO2v5+vLMfazrhl6BzhSd+2k4w8mpE3VBFcwT5iszBG1546bTLjpRu7McSbA7+cCAWMxrN8ESvnWEBAAAAA6yRcDzNmw6AgAsBK4qLqRV2fWvRftGyR0j3mHb65G3cCwMLovzjP6XGOYXxr2jJkaiTzJgpIy2JcYluNORAGiHw+IYnce+xjPVW2tZsEsQaeeC+njhcM3oaFuyeQBdEOrIsiEmi0luivUovCfvqRIIC/tMrJDUoRNIk5GpQrTR/Sm9KdZogJw1eaEbiG/dIaQ=="
      );
      const signature = base64Decode(
        "hF4nqu92D5Ur+2YYeRnEFIs6TdSrCFf4blUOU5nmndtqv+3quh5nssksfE/APTSnMKVg9X44OT7IyqxonIH7xLuNJjBkG7KYma9urLMBCo4x5JoTWPaG1p7URXapIpy1ng+avITVXJin9XQoxPxyNA=="
      );

      const request: BbsCreateProofRequest = {
        signature,
        publicKey: bbsPublicKey,
        messages,
        nonce: randomBytes(10),
        revealed: [0],
      };

      await expect(createProof(request)).rejects.toThrowError(
        "Failed to create proof"
      );
    });

    it("should fail to create proof when attempting to create one with missing messages", async () => {
      const messages = [
        stringToTypedBytes("badmessagex01a=="),
        stringToTypedBytes("PNMnARWIHP+s2g=="),
      ];

      const bbsPublicKey = base64Decode(
        "o6kQ4DspDhUa1Cvo2//bpXBv2SlxV1fblNcRB6p+yEos8pVgivndRjUjm1nNs755Eei6/EOE0DUd8Ph1DSV9gDWwyzjj6EkVVgBRHxjMFM1z7yyOorOO2v5+vLMfazrhl6BzhSd+2k4w8mpE3VBFcwT5iszBG1546bTLjpRu7McSbA7+cCAWMxrN8ESvnWEBAAAAA6yRcDzNmw6AgAsBK4qLqRV2fWvRftGyR0j3mHb65G3cCwMLovzjP6XGOYXxr2jJkaiTzJgpIy2JcYluNORAGiHw+IYnce+xjPVW2tZsEsQaeeC+njhcM3oaFuyeQBdEOrIsiEmi0luivUovCfvqRIIC/tMrJDUoRNIk5GpQrTR/Sm9KdZogJw1eaEbiG/dIaQ=="
      );
      const signature = base64Decode(
        "hF4nqu92D5Ur+2YYeRnEFIs6TdSrCFf4blUOU5nmndtqv+3quh5nssksfE/APTSnMKVg9X44OT7IyqxonIH7xLuNJjBkG7KYma9urLMBCo4x5JoTWPaG1p7URXapIpy1ng+avITVXJin9XQoxPxyNA=="
      );

      const request: BbsCreateProofRequest = {
        signature,
        publicKey: bbsPublicKey,
        messages,
        nonce: randomBytes(10),
        revealed: [0],
      };

      await expect(createProof(request)).rejects.toThrowError(
        "Failed to create proof"
      );
    });

    it("should fail to create proof when attempting to create one with messages supplied in wrong order", async () => {
      const messages = [
        stringToTypedBytes("ti9WYhhEej85jw=="),
        stringToTypedBytes("PNMnARWIHP+s2g=="),
        stringToTypedBytes("J42AxhciOVkE9w=="),
      ];

      const bbsPublicKey = base64Decode(
        "o6kQ4DspDhUa1Cvo2//bpXBv2SlxV1fblNcRB6p+yEos8pVgivndRjUjm1nNs755Eei6/EOE0DUd8Ph1DSV9gDWwyzjj6EkVVgBRHxjMFM1z7yyOorOO2v5+vLMfazrhl6BzhSd+2k4w8mpE3VBFcwT5iszBG1546bTLjpRu7McSbA7+cCAWMxrN8ESvnWEBAAAAA6yRcDzNmw6AgAsBK4qLqRV2fWvRftGyR0j3mHb65G3cCwMLovzjP6XGOYXxr2jJkaiTzJgpIy2JcYluNORAGiHw+IYnce+xjPVW2tZsEsQaeeC+njhcM3oaFuyeQBdEOrIsiEmi0luivUovCfvqRIIC/tMrJDUoRNIk5GpQrTR/Sm9KdZogJw1eaEbiG/dIaQ=="
      );
      const signature = base64Decode(
        "hF4nqu92D5Ur+2YYeRnEFIs6TdSrCFf4blUOU5nmndtqv+3quh5nssksfE/APTSnMKVg9X44OT7IyqxonIH7xLuNJjBkG7KYma9urLMBCo4x5JoTWPaG1p7URXapIpy1ng+avITVXJin9XQoxPxyNA=="
      );

      const request: BbsCreateProofRequest = {
        signature,
        publicKey: bbsPublicKey,
        messages,
        nonce: randomBytes(10),
        revealed: [0],
      };

      await expect(createProof(request)).rejects.toThrowError(
        "Failed to create proof"
      );
    });
  });

  describe("blsCreateProofMulti", () => {
    it("should create proof revealing single message from single message signature", async () => {
      const messages = [[stringToTypedBytes("uzAoQFqLgReidw==")]];
      const blsPublicKey = [
        base64Decode(
          "gPz23LHQrxwlZJpeAuPKou582/+mIJ0+TYmoOBWRGqcGvx2o9aRID/umqLs+tfc9Cf0Hl7w2zzpOPAuhV22nnIRBIS2JNgKPtkoZ3HWC/rF10GzWTbHWIQkqKDvepxX9"
        ),
      ];
      const signature = [
        base64Decode(
          "rqd9lDf2BfHlZ5VMn6Ixf2LuiW6UsChG29S/Qsf6suSDxUil3cZp6ktFhHDd2TedJmSZEgbMbmoURRP0yJmkF+5Rb6RW7j+exRwVndypfDNB/rZ0lrbolzuxr6bvm7HAznsGewibBG0pA8zdMyiI5g=="
        ),
      ];

      const request: BbsCreateProofMultiRequest = {
        signature,
        publicKey: blsPublicKey,
        messages,
        nonce: stringToBytes("0123456789"),
        revealed: [[0]],
        equivs: [],
        range: [[]],
      };

      const proof = await blsCreateProofMulti(request);
      expect(proof.length).toEqual(1);
      expect(proof[0]).toBeInstanceOf(Array);
      expect(proof[0].length).toEqual(389);
    });

    it("should create proof revealing all messages from multi-message signature", async () => {
      const messages = [
        [
          stringToTypedBytes("C+n1rPz1/tVzPg=="),
          stringToTypedBytes("h3x8cbySqC4rLA=="),
          stringToTypedBytes("MGf74ofGdRwNbw=="),
        ],
      ];
      const blsPublicKey = [
        base64Decode(
          "uYrCIgmn8ljb0IGqZTZq2P0YEQWRzl7xcoMmLtGkxa/8JTtPuT81RMIkGulVLj8yBUoB/iMu+7co0HdW0DWzHPQgy257MESx298xFG6uB6KBfWK083g0WCLB+QB4Q7rM"
        ),
      ];
      const signature = [
        base64Decode(
          "qxSZGJTrx19EZoZPMWzfc/7J/qcfO7HWKOOAXU7r070LAlqZrOMOp12alo+JRlMsIGRyCKFCqTh0OmRptTSlGpndfzkcPSD6zHgbdf9UD80utVUUq+Y94x2DXq0A5D5iS0ZHBmNbqQiYD0OAdIgIZQ=="
        ),
      ];

      const request: BbsCreateProofMultiRequest = {
        signature,
        publicKey: blsPublicKey,
        messages,
        nonce: randomBytes(10),
        revealed: [[0, 1, 2]],
        equivs: [],
        range: [[]],
      };

      const proof = await blsCreateProofMulti(request);
      expect(proof.length).toEqual(1);
      expect(proof[0]).toBeInstanceOf(Array);
      expect(proof[0].length).toEqual(389); //TODO add a reason for this and some constants?
    });

    it("should create proof revealing single message from multi-message signature", async () => {
      const messages = [
        [
          stringToTypedBytes("uiSKIfNoO2rMrA=="),
          stringToTypedBytes("lMoHHrFx0LxwAw=="),
          stringToTypedBytes("wdwqLVm9chMMnA=="),
        ],
      ];
      const blsPublicKey = [
        base64Decode(
          "oXMlxldNwkqmbbWc1GBBT0GTd1cOQW0ofcGQegg9y7ZTXS1wbkXbHe2lCDXJHV6ZFJ67AwCgPxbZNGf2a4N9uMocUhnAIoHORYLSHqBG3O7vLXDYRp1kZomlNp6ZLVux"
        ),
      ];
      const signature = [
        base64Decode(
          "qXlIUhC8mhEUaOMRlHExjsbtFug85SG0vExgfFZo2UmUcrLCsVDbIx9u3S4HL2a7IGRyCKFCqTh0OmRptTSlGpndfzkcPSD6zHgbdf9UD80utVUUq+Y94x2DXq0A5D5iS0ZHBmNbqQiYD0OAdIgIZQ=="
        ),
      ];

      const request: BbsCreateProofMultiRequest = {
        signature,
        publicKey: blsPublicKey,
        messages,
        nonce: randomBytes(10),
        revealed: [[0]],
        equivs: [],
        range: [[]],
      };

      const proof = await blsCreateProofMulti(request);
      expect(proof.length).toEqual(1);
      expect(proof[0]).toBeInstanceOf(Array);
      expect(proof[0].length).toEqual(453); //TODO add a reason for this and some constants?
    });

    it("should create proof revealing multiple messages from multi-message signature", async () => {
      const messages = [
        [
          stringToTypedBytes("uiSKIfNoO2rMrA=="),
          stringToTypedBytes("lMoHHrFx0LxwAw=="),
          stringToTypedBytes("wdwqLVm9chMMnA=="),
        ],
      ];
      const blsPublicKey = [
        base64Decode(
          "oXMlxldNwkqmbbWc1GBBT0GTd1cOQW0ofcGQegg9y7ZTXS1wbkXbHe2lCDXJHV6ZFJ67AwCgPxbZNGf2a4N9uMocUhnAIoHORYLSHqBG3O7vLXDYRp1kZomlNp6ZLVux"
        ),
      ];
      const signature = [
        base64Decode(
          "qXlIUhC8mhEUaOMRlHExjsbtFug85SG0vExgfFZo2UmUcrLCsVDbIx9u3S4HL2a7IGRyCKFCqTh0OmRptTSlGpndfzkcPSD6zHgbdf9UD80utVUUq+Y94x2DXq0A5D5iS0ZHBmNbqQiYD0OAdIgIZQ=="
        ),
      ];

      const request: BbsCreateProofMultiRequest = {
        signature,
        publicKey: blsPublicKey,
        messages,
        nonce: randomBytes(10),
        revealed: [[0, 2]],
        equivs: [],
        range: [[]],
      };

      const proof = await blsCreateProofMulti(request);
      expect(proof.length).toEqual(1);
      expect(proof[0]).toBeInstanceOf(Array);
      expect(proof[0].length).toEqual(421); //TODO evaluate this length properly add a reason for this and some constants?
    });

    it("should fail to create proof when attempting to create one with an unsigned extra message", async () => {
      const messages = [
        [
          stringToTypedBytes("uiSKIfNoO2rMrA=="),
          stringToTypedBytes("lMoHHrFx0LxwAw=="),
          stringToTypedBytes("wdwqLVm9chMMnA=="),
          stringToTypedBytes("badmessagex01a=="),
        ],
      ];
      const blsPublicKey = [
        base64Decode(
          "oXMlxldNwkqmbbWc1GBBT0GTd1cOQW0ofcGQegg9y7ZTXS1wbkXbHe2lCDXJHV6ZFJ67AwCgPxbZNGf2a4N9uMocUhnAIoHORYLSHqBG3O7vLXDYRp1kZomlNp6ZLVux"
        ),
      ];
      const signature = [
        base64Decode(
          "qXlIUhC8mhEUaOMRlHExjsbtFug85SG0vExgfFZo2UmUcrLCsVDbIx9u3S4HL2a7IGRyCKFCqTh0OmRptTSlGpndfzkcPSD6zHgbdf9UD80utVUUq+Y94x2DXq0A5D5iS0ZHBmNbqQiYD0OAdIgIZQ=="
        ),
      ];

      const request: BbsCreateProofMultiRequest = {
        signature,
        publicKey: blsPublicKey,
        messages,
        nonce: randomBytes(10),
        revealed: [[0, 1, 2, 3]],
        equivs: [],
        range: [[]],
      };

      await expect(blsCreateProofMulti(request)).rejects.toThrowError(
        "Failed to create proof"
      );
    });

    it("should fail to create proof when attempting to create one with a modified message", async () => {
      const messages = [
        [
          stringToTypedBytes("badmessagex01a=="),
          stringToTypedBytes("lMoHHrFx0LxwAw=="),
          stringToTypedBytes("wdwqLVm9chMMnA=="),
        ],
      ];
      const blsPublicKey = [
        base64Decode(
          "oXMlxldNwkqmbbWc1GBBT0GTd1cOQW0ofcGQegg9y7ZTXS1wbkXbHe2lCDXJHV6ZFJ67AwCgPxbZNGf2a4N9uMocUhnAIoHORYLSHqBG3O7vLXDYRp1kZomlNp6ZLVux"
        ),
      ];
      const signature = [
        base64Decode(
          "qXlIUhC8mhEUaOMRlHExjsbtFug85SG0vExgfFZo2UmUcrLCsVDbIx9u3S4HL2a7IGRyCKFCqTh0OmRptTSlGpndfzkcPSD6zHgbdf9UD80utVUUq+Y94x2DXq0A5D5iS0ZHBmNbqQiYD0OAdIgIZQ=="
        ),
      ];

      const request: BbsCreateProofMultiRequest = {
        signature,
        publicKey: blsPublicKey,
        messages,
        nonce: randomBytes(10),
        revealed: [[0]],
        equivs: [],
        range: [[]],
      };

      await expect(blsCreateProofMulti(request)).rejects.toThrowError(
        "Failed to create proof"
      );
    });

    it("should fail to create proof when attempting to create one with missing messages", async () => {
      const messages = [
        [
          stringToTypedBytes("lMoHHrFx0LxwAw=="),
          stringToTypedBytes("wdwqLVm9chMMnA=="),
        ],
      ];
      const blsPublicKey = [
        base64Decode(
          "oXMlxldNwkqmbbWc1GBBT0GTd1cOQW0ofcGQegg9y7ZTXS1wbkXbHe2lCDXJHV6ZFJ67AwCgPxbZNGf2a4N9uMocUhnAIoHORYLSHqBG3O7vLXDYRp1kZomlNp6ZLVux"
        ),
      ];
      const signature = [
        base64Decode(
          "qXlIUhC8mhEUaOMRlHExjsbtFug85SG0vExgfFZo2UmUcrLCsVDbIx9u3S4HL2a7IGRyCKFCqTh0OmRptTSlGpndfzkcPSD6zHgbdf9UD80utVUUq+Y94x2DXq0A5D5iS0ZHBmNbqQiYD0OAdIgIZQ=="
        ),
      ];

      const request: BbsCreateProofMultiRequest = {
        signature,
        publicKey: blsPublicKey,
        messages,
        nonce: randomBytes(10),
        revealed: [[0]],
        equivs: [],
        range: [[]],
      };

      await expect(blsCreateProofMulti(request)).rejects.toThrowError(
        "Failed to create proof"
      );
    });

    it("should fail to create proof when attempting to create one with a modified message", async () => {
      const messages = [
        [
          stringToTypedBytes("wdwqLVm9chMMnA=="),
          stringToTypedBytes("lMoHHrFx0LxwAw=="),
          stringToTypedBytes("uiSKIfNoO2rMrA=="),
        ],
      ];
      const blsPublicKey = [
        base64Decode(
          "oXMlxldNwkqmbbWc1GBBT0GTd1cOQW0ofcGQegg9y7ZTXS1wbkXbHe2lCDXJHV6ZFJ67AwCgPxbZNGf2a4N9uMocUhnAIoHORYLSHqBG3O7vLXDYRp1kZomlNp6ZLVux"
        ),
      ];
      const signature = [
        base64Decode(
          "qXlIUhC8mhEUaOMRlHExjsbtFug85SG0vExgfFZo2UmUcrLCsVDbIx9u3S4HL2a7IGRyCKFCqTh0OmRptTSlGpndfzkcPSD6zHgbdf9UD80utVUUq+Y94x2DXq0A5D5iS0ZHBmNbqQiYD0OAdIgIZQ=="
        ),
      ];

      const request: BbsCreateProofMultiRequest = {
        signature,
        publicKey: blsPublicKey,
        messages,
        nonce: randomBytes(10),
        revealed: [[0]],
        equivs: [],
        range: [[]],
      };

      await expect(blsCreateProofMulti(request)).rejects.toThrowError(
        "Failed to create proof"
      );
    });
  });
});
