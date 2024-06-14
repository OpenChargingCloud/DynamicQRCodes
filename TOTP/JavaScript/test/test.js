/*
 * Copyright (c) 2024 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of DynamicQRCodes <https://github.com/OpenChargingCloud/DynamicQRCodes>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { expect }        from 'chai';
import { generateTOTPs } from '../TOTP.js';

describe('TOTP Generation Tests', function() {

    it('should generate TOTP codes correctly', function() {

        const sharedSecret = 'secure!Charging!';
        const result       = generateTOTPs(sharedSecret);

        expect(result).to.have.property('previous').     that.is.a('string');
        expect(result).to.have.property('current').      that.is.a('string');
        expect(result).to.have.property('next').         that.is.a('string');
        expect(result).to.have.property('remainingTime').that.is.a('number');

    });

    it('should throw an error for empty shared secret', function() {
        expect(() => generateTOTPs('')).to.throw("The given shared secret must not be null or empty!");
    });

    it('should throw an error for short shared secret', function() {
        expect(() => generateTOTPs('shortSecret')).to.throw("The length of the given shared secret must be at least 16 characters!");
    });

    it('should throw an error for invalid TOTP length', function() {
        expect(() => generateTOTPs('secure!Charging!', 30, 3)).to.throw("The expected length of the TOTP must be between 4 and 255 characters!");
    });

    it('should throw an error for invalid alphabet', function() {
        expect(() => generateTOTPs('secure!Charging!', 30, 12, 'abc')).to.throw("The given alphabet must contain at least 4 characters!");
    });

    it('should throw an error for duplicate characters in alphabet', function() {
        expect(() => generateTOTPs('secure!Charging!', 30, 12, 'abcdeff')).to.throw("The given alphabet must not contain duplicate characters!");
    });

    it('should throw an error for whitespace characters in alphabet', function() {
        expect(() => generateTOTPs('secure!Charging!', 30, 12, 'ab cdef')).to.throw("The given alphabet must not contain any whitespace characters!");
    });




    it('should generate TOTP codes for the given timestamp correctly', function() {

        const sharedSecret = 'secure!Charging!';
        const timestamp    = Date.UTC(2024, 4, 23, 0, 23, 5);
        const result       = generateTOTPs(sharedSecret, null, null, null, timestamp);

        expect(result).to.have.property('previous').     that.equals("MdPU0jCm5tXz");
        expect(result).to.have.property('current').      that.equals("CN63y502maVh");
        expect(result).to.have.property('next').         that.equals("dI54vnA25m2h");
        expect(result).to.have.property('remainingTime').that.equals(25);

    });

    it('should generate TOTP codes with the given length correctly', function() {

        const sharedSecret = 'secure!Charging!';
        const timestamp    = Date.UTC(2024, 4, 23, 0, 23, 5);
        const length       = 23;
        const result       = generateTOTPs(sharedSecret, null, length, null, timestamp);

        expect(result).to.have.property('previous').     that.equals("MdPU0jCm5tXzkaPrPj61KwI");
        expect(result).to.have.property('current').      that.equals("CN63y502maVhAsv27Sd7JlE");
        expect(result).to.have.property('next').         that.equals("dI54vnA25m2hWW3bUcdY13q");
        expect(result).to.have.property('remainingTime').that.equals(25);

    });

    it('should generate TOTP codes with the given alphabet correctly', function() {

        const sharedSecret = 'secure!Charging!';
        const timestamp    = Date.UTC(2024, 4, 23, 0, 23, 5);
        const alphabet     = "0123456789";
        const result       = generateTOTPs(sharedSecret, null, null, alphabet, timestamp);

        expect(result).to.have.property('previous').     that.equals("233045043555");
        expect(result).to.have.property('current').      that.equals("894361286613");
        expect(result).to.have.property('next').         that.equals("545817627227");
        expect(result).to.have.property('remainingTime').that.equals(25);

    });

    it('should generate TOTP codes with the given validity time correctly', function() {

        const sharedSecret = 'secure!Charging!';
        const timestamp    = Date.UTC(2024, 4, 23, 0, 23, 5);
        const validityTime = 60;
        const result       = generateTOTPs(sharedSecret, validityTime, null, null, timestamp);

        expect(result).to.have.property('previous').     that.equals("nTdkiuG6yUyg");
        expect(result).to.have.property('current').      that.equals("XJZr0L1DGKn0");
        expect(result).to.have.property('next').         that.equals("ft0ONZ62MdMj");
        expect(result).to.have.property('remainingTime').that.equals(55);

    });

});
