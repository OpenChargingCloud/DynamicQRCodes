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

import crypto from 'crypto';

function isLittleEndian() {
    const buf = Buffer.alloc(4);
    buf.writeInt32LE(1, 0);
    return buf.readInt32LE(0) === 1;
}

function reverseBytes(buffer) {
    for (let i = 0; i < buffer.length / 2; i++) {
        let temp = buffer[i];
        buffer[i] = buffer[buffer.length - 1 - i];
        buffer[buffer.length - 1 - i] = temp;
    }
}

function bytesToString(bytes) {
    return Array.from(bytes).map(byte => byte.toString()).join('-');
}

function calcTOTPSlot(slotBytes, TOTPLength, alphabet, sharedSecret) {

    // JavaScript's Buffer methods default to big-endian!
    if (!isLittleEndian())
        reverseBytes(slotBytes);

    //console.log(`Slot bytes: ${bytesToString(slotBytes)}`);

    const hmac        = crypto.createHmac('sha256', Buffer.from(sharedSecret, 'utf-8'));
    const currentHash = hmac.update(slotBytes).digest();
    const offset      = currentHash[currentHash.length - 1] & 0x0F;

    let result = '';
    for (let i = 0; i < TOTPLength; i++)
        result += alphabet[currentHash[(offset + i) % currentHash.length] % alphabet.length];

    return result;

}

export function generateTOTPs(SharedSecret,
                              ValidityTime  = null,
                              TOTPLength    = null,
                              Alphabet      = null,
                              Timestamp     = null) {

    if (!ValidityTime) ValidityTime  = 30;
    if (!TOTPLength)   TOTPLength    = 12;
    if (!Alphabet)     Alphabet      = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (!Timestamp)    Timestamp     = Date.now();

    SharedSecret = SharedSecret?.trim();
    Alphabet     = Alphabet?.    trim();

    if (!SharedSecret)                              throw new Error("The given shared secret must not be null or empty!");
    if (/\s/.test(SharedSecret))                    throw new Error("The given shared secret must not contain any whitespace characters!");
    if (SharedSecret.length < 16)                   throw new Error("The length of the given shared secret must be at least 16 characters!");
    if (TOTPLength < 4)                             throw new Error("The expected length of the TOTP must be between 4 and 255 characters!");
    if (!Alphabet)                                  throw new Error("The given alphabet must not be null or empty!");
    if (Alphabet.length < 4)                        throw new Error("The given alphabet must contain at least 4 characters!");
    if (new Set(Alphabet).size !== Alphabet.length) throw new Error("The given alphabet must not contain duplicate characters!");
    if (/\s/.test(Alphabet))                        throw new Error("The given alphabet must not contain any whitespace characters!");

    const currentUnixTime    = Math.floor(Timestamp / 1000);
    const currentSlot        = BigInt(Math.floor(currentUnixTime / ValidityTime));
    const remainingTime      = ValidityTime - (currentUnixTime % ValidityTime);

    // For interoperability we use 8 byte timestamps
    const previousSlotBytes  = Buffer.alloc(8);
    const currentSlotBytes   = Buffer.alloc(8);
    const nextSlotBytes      = Buffer.alloc(8);

    previousSlotBytes.writeBigUInt64BE(currentSlot - BigInt(1));
    currentSlotBytes. writeBigUInt64BE(currentSlot);
    nextSlotBytes.    writeBigUInt64BE(currentSlot + BigInt(1));

    const previous           = calcTOTPSlot(previousSlotBytes, TOTPLength, Alphabet, SharedSecret);
    const current            = calcTOTPSlot(currentSlotBytes,  TOTPLength, Alphabet, SharedSecret);
    const next               = calcTOTPSlot(nextSlotBytes,     TOTPLength, Alphabet, SharedSecret);

    return {
        previous,
        current,
        next,
        remainingTime
    };

}

// Example usage
//const { previousTOTP, currentTOTP, nextTOTP, remainingTime } = generateTOTPs('secure!Charging!');
//console.log(`Generated TOTP: (${previousTOTP}, ${currentTOTP}, ${nextTOTP}, ${remainingTime} milliseconds)`);
