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
  BbsVerifyProofRequest,
  verifyProof,
  blsVerifyProofMulti,
  BbsCreateProofRequest,
  createProof,
  BbsVerifyProofMultiRequest,
} from "../../lib";
import { base64Decode, stringToBytes, stringToTypedBytes } from "../utilities";

describe("bbsSignature", () => {
  describe("verifyProof", () => {
    it("should verify proof with all messages revealed from single message signature", async () => {
      const messages = [stringToTypedBytes("RmtnDBJHso5iSg==")];
      const bbsPublicKey = base64Decode(
        "uI9+d9OZ2Yzl5zMmWltuBvFjUKLs+Q9wiuTtzqZwE3tzfRwmf6aPNoBCOF2Zwyc/B3qhjwStqFDLKyy6xott9WAGTlVwwA4igwJwtXaF6jeHfkwvfbvuI155QPg+pigmgiAr/dcHklf5+4yaPpq7+SBgzUKknTYR6uC7RemOdS058q14/s/UTcyG71pvxyH5AAAAAYNH/5xWsNqf3MSYCTzFgxqrlLM+DaJYu1FP84Hb6KKzcI1RHoux8kDXBVF32StjOg=="
      );
      const proof = base64Decode(
        "AAEBrfLs1vgToUaRy4eYdztbex1pym3gKuLQWF/pzjYb/Wjd5dH0aZIIYeAlsEGZNxpXkxDgBX9xcvVT40eesCRPxTsMXqCzWkVlPXL6Sma14qsBFhWgLVTyslwUH5yQJqPrjdEQ/KHd2a1suB/kg3axtuN682jXjWfIbA644Jww5hPHBqxBKZPKiCMAGOgagnGzAAAAdLWIAIygb2KKXI3fWLIZZPYJU/Nvcvj6hyBFSMVDNKueyZlW3qwezEHGW0Le3MO7xQAAAAJtnxFXCDhV6m6+CAEWwbkgM5ZlWfSsaCjCuGMqCURUAWzgggu45uS64ISoXvSsWh/sNDIfEfJ6DR5R84WTLhQmhzPbZUoDgWO00HiismRjixbwNs+X34yHRk2niyqxi1abDdM0RqCDz9E8ilHRqSmJAAAAAmuC/CIUecIeE3AnZtuN6t8iLmCU2znfID4ICk2vM3wbNN+5/fgFS/Ops9qeiYS739W63zK66ZjfVuG26qnTIf8="
      );

      const request: BbsVerifyProofRequest = {
        proof,
        publicKey: bbsPublicKey,
        messages,
        nonce: stringToBytes("0123456789"),
      };

      expect((await verifyProof(request)).verified).toBeTruthy();
    });

    it("should verify proof with all messages revealed from multi message signature", async () => {
      const messages = [
        stringToTypedBytes("J42AxhciOVkE9w=="),
        stringToTypedBytes("PNMnARWIHP+s2g=="),
        stringToTypedBytes("ti9WYhhEej85jw=="),
      ];
      const bbsPublicKey = base64Decode(
        "o6kQ4DspDhUa1Cvo2//bpXBv2SlxV1fblNcRB6p+yEos8pVgivndRjUjm1nNs755Eei6/EOE0DUd8Ph1DSV9gDWwyzjj6EkVVgBRHxjMFM1z7yyOorOO2v5+vLMfazrhl6BzhSd+2k4w8mpE3VBFcwT5iszBG1546bTLjpRu7McSbA7+cCAWMxrN8ESvnWEBAAAAA6yRcDzNmw6AgAsBK4qLqRV2fWvRftGyR0j3mHb65G3cCwMLovzjP6XGOYXxr2jJkaiTzJgpIy2JcYluNORAGiHw+IYnce+xjPVW2tZsEsQaeeC+njhcM3oaFuyeQBdEOrIsiEmi0luivUovCfvqRIIC/tMrJDUoRNIk5GpQrTR/Sm9KdZogJw1eaEbiG/dIaQ=="
      );
      const proof = base64Decode(
        "AAMHq97XY3TlqkAoab92d9gjpERP/hjqWtmAmvMJ73Lp/ORQp6vzIOzcZh+2pHjCbFlitWOPuhK12jIIq3B72cQBWl9ut/uvyyhDYXUWh0BGS59vF9vRcGKugV9uWgr6hZZhmFY7o1Dteg9labYfZzI8AZ1smI4fFp0ferc6OUSE0SNV3Acv31XPbDHUCGdTzk61AAAAdJXQP8AXQh+f3tbvJKPFK0QJmLrRlKRct5Lzk6jv9XDSasTy2UJplJFxVwvX18cHLQAAAAJHmrjLqQVmI6ran5qsABsruOyxSeJoxqQr3ucY6+wbkyQNPH/MVJeVelUXa7P3JnXXINASnUgbD9AQeZnzHvQ0iFDiyItTD2shb4PYAtDILMT5SIM4iZ7hmJikgqQx77xI/o5bsqZ/oe9vgEcH82zmAAAAAkeodzkxp2OGnknDwd9gGoRR9uof+XhiWA1HF6zknU8+E21Eb/2P3aOzZXxusVVhZixAL7mpyy3RTMEKYbJhMbA="
      );

      const request: BbsVerifyProofRequest = {
        proof,
        publicKey: bbsPublicKey,
        messages,
        nonce: stringToBytes("Fo7NBbX3UFKj2w=="),
      };

      expect((await verifyProof(request)).verified).toBeTruthy();
    });

    it("should verify proof with one message revealed from multi-message signature", async () => {
      const messages = [
        stringToTypedBytes("J42AxhciOVkE9w=="),
        stringToTypedBytes("PNMnARWIHP+s2g=="),
        stringToTypedBytes("ti9WYhhEej85jw=="),
      ];
      const bbsPublicKey = base64Decode(
        "o6kQ4DspDhUa1Cvo2//bpXBv2SlxV1fblNcRB6p+yEos8pVgivndRjUjm1nNs755Eei6/EOE0DUd8Ph1DSV9gDWwyzjj6EkVVgBRHxjMFM1z7yyOorOO2v5+vLMfazrhl6BzhSd+2k4w8mpE3VBFcwT5iszBG1546bTLjpRu7McSbA7+cCAWMxrN8ESvnWEBAAAAA6yRcDzNmw6AgAsBK4qLqRV2fWvRftGyR0j3mHb65G3cCwMLovzjP6XGOYXxr2jJkaiTzJgpIy2JcYluNORAGiHw+IYnce+xjPVW2tZsEsQaeeC+njhcM3oaFuyeQBdEOrIsiEmi0luivUovCfvqRIIC/tMrJDUoRNIk5GpQrTR/Sm9KdZogJw1eaEbiG/dIaQ=="
      );
      const proof = base64Decode(
        "AAMBglqcHQmNlJ6UFVlzvc8BxRLdwKCusNSrCU79VxDt2LJYYb3lrhoFHf/t8rNVxPxEkpz6xVJA6nk1qIeG+G99o5p4m2RZ9QGLzf0KczPj4FTM5/Dw3ac+jx12ylChqrlqj00jDZKYAAR4C+AcMIbQqb6A4QNP9FJu57vaY+s+MyGS+9pUXs5Vu9hs3nJnXkzSAAAAdIMAWzIzo0pj2OezgEY4Wpc+7C+hGQIdFEJA+gfmy7VuriNw/HJkxUgsd6e+MmfFLwAAAAIWnhGH7qqC4a4rIFsw6OfY1xAL5Ouj1Zmvk1W9nDfhmVPTeZCtdC/H7wDdP+sOWOsNDpKmuz/g81YRUjLUdmpcmT3bwA4bV8FKRfn4MTMv2VtWwX+n5arQuYtVXK3vu9UnDNJ6qyKwpgIRytq2angvAAAABALidWJJvI6EaL6iov/PsqJ8Cb6lOtkvAUUqkNjk74OLTcsbUzUj0HXBAvfcyQGeLTNf390QuHm4deWuDBlYKckv+Aq/4/a4xry3Ubz9a7FqJhuG95COMK08gNcWUSf0kGxdcJ0CUwQ4WTGY5U8uyxjNGhd5Gs6PKqiEkoghycbj"
      );

      const revealedMessages = messages.slice(0, 1);

      const request: BbsVerifyProofRequest = {
        proof,
        publicKey: bbsPublicKey,
        messages: revealedMessages,
        nonce: stringToBytes("NoWZhtX+u1wWLtUfPMmku1FtU2I="),
      };

      expect((await verifyProof(request)).verified).toBeTruthy();
    });

    it("should not verify with bad nonce", async () => {
      const messages = [stringToTypedBytes("RmtnDBJHso5iSg==")];
      const bbsPublicKey = base64Decode(
        "uI9+d9OZ2Yzl5zMmWltuBvFjUKLs+Q9wiuTtzqZwE3tzfRwmf6aPNoBCOF2Zwyc/B3qhjwStqFDLKyy6xott9WAGTlVwwA4igwJwtXaF6jeHfkwvfbvuI155QPg+pigmgiAr/dcHklf5+4yaPpq7+SBgzUKknTYR6uC7RemOdS058q14/s/UTcyG71pvxyH5AAAAAYNH/5xWsNqf3MSYCTzFgxqrlLM+DaJYu1FP84Hb6KKzcI1RHoux8kDXBVF32StjOg=="
      );
      const proof = base64Decode(
        "AAEBrfLs1vgToUaRy4eYdztbex1pym3gKuLQWF/pzjYb/Wjd5dH0aZIIYeAlsEGZNxpXkxDgBX9xcvVT40eesCRPxTsMXqCzWkVlPXL6Sma14qsBFhWgLVTyslwUH5yQJqPrjdEQ/KHd2a1suB/kg3axtuN682jXjWfIbA644Jww5hPHBqxBKZPKiCMAGOgagnGzAAAAdLWIAIygb2KKXI3fWLIZZPYJU/Nvcvj6hyBFSMVDNKueyZlW3qwezEHGW0Le3MO7xQAAAAJtnxFXCDhV6m6+CAEWwbkgM5ZlWfSsaCjCuGMqCURUAWzgggu45uS64ISoXvSsWh/sNDIfEfJ6DR5R84WTLhQmhzPbZUoDgWO00HiismRjixbwNs+X34yHRk2niyqxi1abDdM0RqCDz9E8ilHRqSmJAAAAAmuC/CIUecIeE3AnZtuN6t8iLmCU2znfID4ICk2vM3wbNN+5/fgFS/Ops9qeiYS739W63zK66ZjfVuG26qnTIf8="
      );

      const request: BbsVerifyProofRequest = {
        proof,
        publicKey: bbsPublicKey,
        messages,
        nonce: stringToBytes("bad"),
      };

      expect((await verifyProof(request)).verified).toBeFalsy();
    });

    it("should not verify with a message that wasn't signed", async () => {
      // Expects messages to be ["J42AxhciOVkE9w==", "PNMnARWIHP+s2g==", "ti9WYhhEej85jw=="];
      const messages = [
        stringToTypedBytes("MODIFIED"),
        stringToTypedBytes("PNMnARWIHP+s2g=="),
        stringToTypedBytes("ti9WYhhEej85jw=="),
      ];
      const bbsPublicKey = base64Decode(
        "o6kQ4DspDhUa1Cvo2//bpXBv2SlxV1fblNcRB6p+yEos8pVgivndRjUjm1nNs755Eei6/EOE0DUd8Ph1DSV9gDWwyzjj6EkVVgBRHxjMFM1z7yyOorOO2v5+vLMfazrhl6BzhSd+2k4w8mpE3VBFcwT5iszBG1546bTLjpRu7McSbA7+cCAWMxrN8ESvnWEBAAAAA6yRcDzNmw6AgAsBK4qLqRV2fWvRftGyR0j3mHb65G3cCwMLovzjP6XGOYXxr2jJkaiTzJgpIy2JcYluNORAGiHw+IYnce+xjPVW2tZsEsQaeeC+njhcM3oaFuyeQBdEOrIsiEmi0luivUovCfvqRIIC/tMrJDUoRNIk5GpQrTR/Sm9KdZogJw1eaEbiG/dIaQ=="
      );
      const proof = base64Decode(
        "AAMHq97XY3TlqkAoab92d9gjpERP/hjqWtmAmvMJ73Lp/ORQp6vzIOzcZh+2pHjCbFlitWOPuhK12jIIq3B72cQBWl9ut/uvyyhDYXUWh0BGS59vF9vRcGKugV9uWgr6hZZhmFY7o1Dteg9labYfZzI8AZ1smI4fFp0ferc6OUSE0SNV3Acv31XPbDHUCGdTzk61AAAAdJXQP8AXQh+f3tbvJKPFK0QJmLrRlKRct5Lzk6jv9XDSasTy2UJplJFxVwvX18cHLQAAAAJHmrjLqQVmI6ran5qsABsruOyxSeJoxqQr3ucY6+wbkyQNPH/MVJeVelUXa7P3JnXXINASnUgbD9AQeZnzHvQ0iFDiyItTD2shb4PYAtDILMT5SIM4iZ7hmJikgqQx77xI/o5bsqZ/oe9vgEcH82zmAAAAAkeodzkxp2OGnknDwd9gGoRR9uof+XhiWA1HF6zknU8+E21Eb/2P3aOzZXxusVVhZixAL7mpyy3RTMEKYbJhMbA="
      );

      const request: BbsVerifyProofRequest = {
        proof,
        publicKey: bbsPublicKey,
        messages,
        nonce: stringToBytes("Fo7NBbX3UFKj2w=="),
      };

      expect((await verifyProof(request)).verified).toBeFalsy();
    });

    it("should not verify with malformed proof", async () => {
      const messages = [
        stringToTypedBytes("J42AxhciOVkE9w=="),
        stringToTypedBytes("PNMnARWIHP+s2g=="),
        stringToTypedBytes("ti9WYhhEej85jw=="),
      ];
      const bbsPublicKey = base64Decode(
        "o6kQ4DspDhUa1Cvo2//bpXBv2SlxV1fblNcRB6p+yEos8pVgivndRjUjm1nNs755Eei6/EOE0DUd8Ph1DSV9gDWwyzjj6EkVVgBRHxjMFM1z7yyOorOO2v5+vLMfazrhl6BzhSd+2k4w8mpE3VBFcwT5iszBG1546bTLjpRu7McSbA7+cCAWMxrN8ESvnWEBAAAAA6yRcDzNmw6AgAsBK4qLqRV2fWvRftGyR0j3mHb65G3cCwMLovzjP6XGOYXxr2jJkaiTzJgpIy2JcYluNORAGiHw+IYnce+xjPVW2tZsEsQaeeC+njhcM3oaFuyeQBdEOrIsiEmi0luivUovCfvqRIIC/tMrJDUoRNIk5GpQrTR/Sm9KdZogJw1eaEbiG/dIaQ=="
      );
      const proof = base64Decode(
        "badAAMHq97XY3TlqkAoab92d9gjpERP/hjqWtmAmvMJ73Lp/ORQp6vzIOzcZh+2pHjCbFlitWOPuhK12jIIq3B72cQBWl9ut/uvyyhDYXUWh0BGS59vF9vRcGKugV9uWgr6hZZhmFY7o1Dteg9labYfZzI8AZ1smI4fFp0ferc6OUSE0SNV3Acv31XPbDHUCGdTzk61AAAAdJXQP8AXQh+f3tbvJKPFK0QJmLrRlKRct5Lzk6jv9XDSasTy2UJplJFxVwvX18cHLQAAAAJHmrjLqQVmI6ran5qsABsruOyxSeJoxqQr3ucY6+wbkyQNPH/MVJeVelUXa7P3JnXXINASnUgbD9AQeZnzHvQ0iFDiyItTD2shb4PYAtDILMT5SIM4iZ7hmJikgqQx77xI/o5bsqZ/oe9vgEcH82zmAAAAAkeodzkxp2OGnknDwd9gGoRR9uof+XhiWA1HF6zknU8+E21Eb/2P3aOzZXxusVVhZixAL7mpyy3RTMEKYbJhMbA="
      );

      const request: BbsVerifyProofRequest = {
        proof,
        publicKey: bbsPublicKey,
        messages,
        nonce: stringToBytes("Fo7NBbX3UFKj2w=="),
      };

      expect((await verifyProof(request)).verified).toBeFalsy();
    });

    it("should not verify with revealed message that was supposed to be hidden", async () => {
      const messages = [
        stringToTypedBytes("Message1"),
        stringToTypedBytes("Message2"),
        stringToTypedBytes("Message3"),
        stringToTypedBytes("Message4"),
      ];
      const signature = base64Decode(
        "sT5d1fB9cv8eOhk34cPbyzFwsP9Cy5KqZ9A8aO9QeCIYtF8ABAzJ0WcDhy0rLIJTBZv2+0Ch0WCIYewp/jE2bGDy4XALHFGj8hM5lW5hB4kio0Kglkol4OlKw+eZ8ujstHAB9XhFu7/XwAcKOB02TQ=="
      );
      const bbsPublicKey = base64Decode(
        "qs+sHnAkXVbMhFviwhxtBHM2ilETZ01hjClxwWRaWUCeJ6FLA7ORpiLv/DQnceZnDTIulGnJniRnjepMpZEDjxMBso6DI+txZ6Z1as556E1wr94kcmfLHvdV2QPzD32AmFGosz9mlY96YGn3C2lxWq2D/+OIsg//ZqO/vSAcTzK5YN5pLqAcxYsbru1WZEd9AAAABI96mUZvct1nvBjEmsQSzlBrH+wWV+lQ9BgrXBSGFEQc9B+L3qho7DIUxZD9+nJU45cv16ghPQGeH9wBG1fnbom3JTHZSKycAESRBGx9rd2uD4TuVpBwjeVfgglT6iyMH4PEQ5P5aSAuPIOVaet6zeyyLwMkvilBVo2S1amSu5spzAibrblbwDznA220mXG9arJSKpA69RTMJMmBtZAvq9avFJe4RqOocG2pbl7wiuc+DG8XSnGEDvkZUwgNdh16JQ=="
      );
      const nonce = stringToBytes("0123456789");

      const proofRequest: BbsCreateProofRequest = {
        signature,
        publicKey: bbsPublicKey,
        messages,
        revealed: [0],
        nonce,
      };
      const proof = await createProof(proofRequest);

      let proofMessages = [stringToTypedBytes("BadMessage9")];
      let request = {
        proof,
        publicKey: bbsPublicKey,
        messageCount: 4,
        messages: proofMessages,
        nonce,
        revealed: [0],
      };

      expect((await verifyProof(request)).verified).toBeFalsy();

      proofMessages = [stringToTypedBytes("Message1")];
      request = {
        proof,
        publicKey: bbsPublicKey,
        messageCount: 4,
        messages: proofMessages,
        nonce,
        revealed: [0],
      };
      expect((await verifyProof(request)).verified).toBeTruthy();
    });
  });

  describe("blsVerifyProofMulti", () => {
    it("should verify proof with all messages revealed from single message signature", async () => {
      const messages = [
        [stringToTypedBytes("uzAoQFqLgReidw==")]
      ];
      const blsPublicKey = [
        base64Decode(
          "gPz23LHQrxwlZJpeAuPKou582/+mIJ0+TYmoOBWRGqcGvx2o9aRID/umqLs+tfc9Cf0Hl7w2zzpOPAuhV22nnIRBIS2JNgKPtkoZ3HWC/rF10GzWTbHWIQkqKDvepxX9"
        )
      ];
      const proof = [
        base64Decode(
          "owABAVkBfLicOuj3R9HL/lB65M8lbFBnvKVc8DO/D8OWCSFpB9kWt2N00ZasDPhUmlNYIo75OYdXfTX8GPoDyoT8H0/91pwWyQ7zQNw2rHzXXVer3edTZx03oXRly5vj/TNh9YCNJ5HYJy2j284iJPGOgOvAj/SDH3dHcOqxwSkUwf+H964P6d27x3FKhGgyFY4DTNombAAAAHSnla1N6oHCUqjuqQY/A8WkhMm0qyYWbokTJTYInjo1bylDF1ifvLmsKidXQF2eOTEAAAACBrSB4hGo9EfAEMtSTgskNkdlvSyVnnK9Gq22fs/X/60t/B6w588VmEqwwAbVGt7e/At8yUap1lins8W12dVX/quTOcFU0DCHMi8ppm7lnCrKkGn8MAhcH/1SRz+fJq0QkTTttNaAF7hMALxnKAiCmgAAAAI35Z228w00MMbDMbPLGLfQmtzcAMS17JFqGBKALWWD/BiFCQHY0eX+4EfN95VhrL1Mjz0tSJHOOzTmnDRxAjxbAoA="
        )
      ];

      const request: BbsVerifyProofMultiRequest = {
        proof,
        publicKey: blsPublicKey,
        messages,
        nonce: stringToBytes("0123456789"),
        revealed: [[0]],
        equivs: [],
        range: [[]],
      };

      expect((await blsVerifyProofMulti(request)).verified).toBeTruthy();
    });

    it("should verify proof with all messages revealed from multi message signature", async () => {
      const messages = [
        [
          stringToTypedBytes("C+n1rPz1/tVzPg=="),
          stringToTypedBytes("h3x8cbySqC4rLA=="),
          stringToTypedBytes("MGf74ofGdRwNbw=="),
        ]
      ];
      const blsPublicKey = [
        base64Decode(
          "uYrCIgmn8ljb0IGqZTZq2P0YEQWRzl7xcoMmLtGkxa/8JTtPuT81RMIkGulVLj8yBUoB/iMu+7co0HdW0DWzHPQgy257MESx298xFG6uB6KBfWK083g0WCLB+QB4Q7rM"
        )
      ];
      const proof = [
        base64Decode(
          "owADAVkBfLAcPXpuWAtqgGf0FpG3UCUjqX4Uk4ODZl8JX4Xi87HZTMkpahvbjpATm9gx864HsIW89qWAKiJuNyCqa7qLx052Gh3Oc3Mh5OsRltyBs5LTjgmIgzPwWxwrB6JWizfQDLfp94yhlyvz98a6mi+g4L6Zfg5vRIaF2fhDYjBZrGFZOwynlw9BL2IzNviWtmKi3AAAAHS50M3sXyy09aHx+qR1z1nAlKp+Y0WpyIOMhFcaCGuq/urnCWQINYSF9wz967YD8twAAAACUBtjRv9FJilgf2kZFy+kIf5incpjZFbaBytqYnqibv9VUWAmra+ZnseBorui2DcaKPYa8xgiJGGFFpp1iXeBd5cvfCn2uF51PQqp+BwF4wfbtiyN13siEQxQH04REMUiy9KVAcHvCGFSS3nrQ9zL2gAAAAJolmEzL9TTlby2s7BEf3umGDY2ELXA+ERiiUD8N0qIgSOu3LEJM7YZ00niL1XJRMpF1HHW8P6Ktkpsh5SyXZaIAoA="
        )
      ];

      const request: BbsVerifyProofMultiRequest = {
        proof,
        publicKey: blsPublicKey,
        messages,
        nonce: stringToBytes("ujMevaaq2n7Cg3ZLzXktqT/WRgM="),
        revealed: [[0, 1, 2]],
        equivs: [],
        range: [[]],
      };

      expect((await blsVerifyProofMulti(request)).verified).toBeTruthy();
    });

    it("should verify proof with multiple messages revealed from multi-message signature", async () => {
      const messages = [
        [
          stringToTypedBytes("uiSKIfNoO2rMrA=="),
          stringToTypedBytes("lMoHHrFx0LxwAw=="),
          stringToTypedBytes("wdwqLVm9chMMnA=="),
        ]
      ];
      const blsPublicKey = [
        base64Decode(
          "oXMlxldNwkqmbbWc1GBBT0GTd1cOQW0ofcGQegg9y7ZTXS1wbkXbHe2lCDXJHV6ZFJ67AwCgPxbZNGf2a4N9uMocUhnAIoHORYLSHqBG3O7vLXDYRp1kZomlNp6ZLVux"
        )
      ];
      const proof = [
        base64Decode(
          "owADAVkBnJmxRjTS4KX25agfDCeIxlt7ZWYw2FvQxLct+gen89QyANunh+bzT6g5DUJY9abOOITAS7udJ7XoVlc59qEjvK9t1lsMMKcyecXH/COd+vCLWI3UaiDiGYFoHlSFkvYHM4pOb2LXppGaRWF/Z0FqZdQ1MSqUAxKyh89YK/X3xZo64Xkp2ni5ecMKWIUaQKwo3AAAAHSBsBg0SjDLslp2co9lG7FptyVcE5hcy5iMh7EjbKJIcNqMlIbRmg1DhS3DGNHZDe8AAAACCVYFObLBcU7GtSy8V+GqVWnHDMs/0ar1pHnnoMrMJRIXF2d+pdm9UQdcAPNqU2QDdZ+eCSjuNQRkBlYVsZFfzLkYWbzRsBVgC1W7Q5ZEx79cGwJYZNVLZK8hzAx3iBs6wOiytriRp58SH/rh4oIT9QAAAANYZooifWanBn5yp53q0M7lfAeHzkEhaWE1Q8g49WEAxFg5vxbo1KXsNIkaK9zvUp8QYN02YFLws1uGyO9PDVxZROnjt1OQ9f0M8BeWFuzfaPf37rro+cHoLb/XwnZuVbwCgA=="
        )
      ];

      const revealedMessages = [
        [
          stringToTypedBytes("uiSKIfNoO2rMrA=="),
          // stringToTypedBytes("lMoHHrFx0LxwAw=="),
          stringToTypedBytes("wdwqLVm9chMMnA=="),
        ]
      ];

      const request: BbsVerifyProofMultiRequest = {
        proof,
        publicKey: blsPublicKey,
        messages: revealedMessages,
        nonce: base64Decode("csBYAufrvE1zkg=="),
        revealed: [[0, 2]],
        equivs: [],
        range: [[]],
      };
      const result = await blsVerifyProofMulti(request);
      expect(result.verified).toBeTruthy();
    });

    it("should verify proof with one message revealed from multi-message signature", async () => {
      const messages = [
        [
          stringToTypedBytes("uiSKIfNoO2rMrA=="),
          stringToTypedBytes("lMoHHrFx0LxwAw=="),
          stringToTypedBytes("wdwqLVm9chMMnA=="),
        ]
      ];
      const blsPublicKey = [
        base64Decode(
          "oXMlxldNwkqmbbWc1GBBT0GTd1cOQW0ofcGQegg9y7ZTXS1wbkXbHe2lCDXJHV6ZFJ67AwCgPxbZNGf2a4N9uMocUhnAIoHORYLSHqBG3O7vLXDYRp1kZomlNp6ZLVux"
        )
      ];
      const proof = [
        base64Decode(
          "owADAVkBvIbCkxzcqLWJi5uKzULJOiYaenw28Taz26QI/v7U3fEOYHmV0xs+E0tLqW2o2FqAQIGp3Wz8HIN3bFLf46hpHdYNM7ZDEbIYNLQEKYN33fKHZfHt9FRGzgXo02E8uSenXIpxAbposm+m1pa2UDNug9SDbt6a8XHmEZvpXzfc+rjullbxLpqjCoXehOd9YspjCQAAAHSJAEh0NfDV2zeyDpLeVSH+CWGZXz0liftbPV0Ir6PToOVslcJ3L51V7sauexUFcycAAAACOiM0D6I9Kzi/GrzUacqaj/kOF/9zJ9exvr0EGOGf75Qo2KHbF8wJSrwG5NArjVuxGQtKmMtWWRoF3Uvkiw7TD5gGNSHW6Z9ANzk7Xp4q1Kc4KuBWGpGjlVogVoS8u06b/jSkmnU7e1we1FMdkEsV0QAAAAQms1WV0/m+V6xfvtXQWmA9wl6Oh6Q5UvwUsJPKXWbkLy63wd6iMXDUQY8KoNpkXTqtX2E1p3jXKfzgxnAqKDeiV2WWEDSRx+2BneLC2VA1EucGy0GInd05q+vjKHN7KfsW42dfngq7NWp3dsGN+nW2J9dhz1UWiWGEqlgVu5AAGwKA"
        )
      ];

      const revealedMessages = [
        [
          stringToTypedBytes("uiSKIfNoO2rMrA=="),
          // stringToTypedBytes("lMoHHrFx0LxwAw=="),
          // stringToTypedBytes("wdwqLVm9chMMnA=="),
        ]
      ];

      const request: BbsVerifyProofMultiRequest = {
        proof,
        publicKey: blsPublicKey,
        messages: revealedMessages,
        nonce: stringToBytes("I03DvFXcpVdOPuOiyXgcBf4voAA="),
        revealed: [[0]],
        equivs: [],
        range: [[]],
      };

      expect((await blsVerifyProofMulti(request)).verified).toBeTruthy();
    });

    it("should not verify with malformed proof", async () => {
      const messages = [
        [
          stringToTypedBytes("C+n1rPz1/tVzPg=="),
          stringToTypedBytes("h3x8cbySqC4rLA=="),
          stringToTypedBytes("MGf74ofGdRwNbw=="),
        ]
      ];
      const blsPublicKey = [
        base64Decode(
          "uYrCIgmn8ljb0IGqZTZq2P0YEQWRzl7xcoMmLtGkxa/8JTtPuT81RMIkGulVLj8yBUoB/iMu+7co0HdW0DWzHPQgy257MESx298xFG6uB6KBfWK083g0WCLB+QB4Q7rM"
        )
      ];
      const proof = [
        base64Decode(
          "owADAVkBfLAcPXpuWAtqgGf0FpG3UCUjqX4Uk4ODZl8JX4Xi87HZTMkpahvbjpATm9gx864HsIW89qWAKiJuNyCqa7qLx052Gh3Oc3Mh5OsRltyBs5LTjgmIgzPwWxwrB6JWizfQDLfp94yhlyvz98a6mi+g4L6Zfg5vRIaF2fhDYjBZrGFZOwynlw9BL2IzNviWtmKi3AAAAHS50M3sXyy09aHx+qR1z1nAlKp+Y0WpyIOMhFcaCGuq/urnCWQINYSF9wz967YD8twAAAACUBtjRv9FJilgf2kZFy+kIf5incpjZFbaBytqYnqibv9VUWAmra+ZnseBorui2DcaKPYa8xgiJGGFFpp1iXeBd5cvfCn2uF51PQqp+BwF4wfbtiyN13siEQxQH04REMUiy9KVAcHvCGFSS3nrQ9zL2gAAAAJolmEzL9TTlby2s7BEf3umGDY2ELXA+ERiiUD8N0qIgSOu3LEJM7YZ00niL1XJRMpF1HHW8P6Ktkpsh5SyXZaIAoA="
        )
      ];
      const request: BbsVerifyProofMultiRequest = {
        proof,
        publicKey: blsPublicKey,
        messages,
        nonce: stringToBytes("ujMevaaq2n7Cg3ZLzXktqT/WRgM="),
        revealed: [[0, 1, 2]],
        equivs: [],
        range: [[]],
      };
      const result = await blsVerifyProofMulti(request);
      expect(result.verified).toBeTruthy();

      const proofBad = [
        base64Decode(
          "BADowADAVkBfLAcPXpuWAtqgGf0FpG3UCUjqX4Uk4ODZl8JX4Xi87HZTMkpahvbjpATm9gx864HsIW89qWAKiJuNyCqa7qLx052Gh3Oc3Mh5OsRltyBs5LTjgmIgzPwWxwrB6JWizfQDLfp94yhlyvz98a6mi+g4L6Zfg5vRIaF2fhDYjBZrGFZOwynlw9BL2IzNviWtmKi3AAAAHS50M3sXyy09aHx+qR1z1nAlKp+Y0WpyIOMhFcaCGuq/urnCWQINYSF9wz967YD8twAAAACUBtjRv9FJilgf2kZFy+kIf5incpjZFbaBytqYnqibv9VUWAmra+ZnseBorui2DcaKPYa8xgiJGGFFpp1iXeBd5cvfCn2uF51PQqp+BwF4wfbtiyN13siEQxQH04REMUiy9KVAcHvCGFSS3nrQ9zL2gAAAAJolmEzL9TTlby2s7BEf3umGDY2ELXA+ERiiUD8N0qIgSOu3LEJM7YZ00niL1XJRMpF1HHW8P6Ktkpsh5SyXZaIAoA="
        )
      ];
      const requestBad: BbsVerifyProofMultiRequest = {
        proof: proofBad,
        publicKey: blsPublicKey,
        messages,
        nonce: stringToBytes("ujMevaaq2n7Cg3ZLzXktqT/WRgM="),
        revealed: [[0, 1, 2]],
        equivs: [],
        range: [[]],
      };
      const resultBad = await blsVerifyProofMulti(requestBad);
      expect(resultBad.verified).toBeFalsy();
    });

    it("should not verify with bad nonce", async () => {
      const messages = [
        [stringToTypedBytes("uzAoQFqLgReidw==")]
      ];
      const blsPublicKey = [
        base64Decode(
          "gPz23LHQrxwlZJpeAuPKou582/+mIJ0+TYmoOBWRGqcGvx2o9aRID/umqLs+tfc9Cf0Hl7w2zzpOPAuhV22nnIRBIS2JNgKPtkoZ3HWC/rF10GzWTbHWIQkqKDvepxX9"
        )
      ];
      const proof = [
        base64Decode(
          "owABAVkBfLicOuj3R9HL/lB65M8lbFBnvKVc8DO/D8OWCSFpB9kWt2N00ZasDPhUmlNYIo75OYdXfTX8GPoDyoT8H0/91pwWyQ7zQNw2rHzXXVer3edTZx03oXRly5vj/TNh9YCNJ5HYJy2j284iJPGOgOvAj/SDH3dHcOqxwSkUwf+H964P6d27x3FKhGgyFY4DTNombAAAAHSnla1N6oHCUqjuqQY/A8WkhMm0qyYWbokTJTYInjo1bylDF1ifvLmsKidXQF2eOTEAAAACBrSB4hGo9EfAEMtSTgskNkdlvSyVnnK9Gq22fs/X/60t/B6w588VmEqwwAbVGt7e/At8yUap1lins8W12dVX/quTOcFU0DCHMi8ppm7lnCrKkGn8MAhcH/1SRz+fJq0QkTTttNaAF7hMALxnKAiCmgAAAAI35Z228w00MMbDMbPLGLfQmtzcAMS17JFqGBKALWWD/BiFCQHY0eX+4EfN95VhrL1Mjz0tSJHOOzTmnDRxAjxbAoA="
        )
      ];

      const request: BbsVerifyProofMultiRequest = {
        proof,
        publicKey: blsPublicKey,
        messages,
        nonce: stringToBytes("0123456789"),
        revealed: [[0]],
        equivs: [],
        range: [[]],
      };

      expect((await blsVerifyProofMulti(request)).verified).toBeTruthy();

      const requestBad: BbsVerifyProofMultiRequest = {
        proof,
        publicKey: blsPublicKey,
        messages,
        nonce: stringToBytes("bad"),
        revealed: [[0]],
        equivs: [],
        range: [[]],
      };

      expect((await blsVerifyProofMulti(requestBad)).verified).toBeFalsy();
    });
  });
});
