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

function isLittleEndian() {
    const buf = new ArrayBuffer(4);
    new DataView(buf).setUint32(0, 1, true);
    return new Uint32Array(buf)[0] === 1;
}

function reverseBytes(buffer) {
    for (let i = 0; i < buffer.length / 2; i++) {
        let temp = buffer[i];
        buffer[i] = buffer[buffer.length - 1 - i];
        buffer[buffer.length - 1 - i] = temp;
    }
}

function hexStringToByteArray(hexString) {
    if (hexString.length % 2 !== 0) {
        throw new Error("Hex string must have an even number of characters");
    }
    const byteArray = new Uint8Array(hexString.length / 2);
    for (let i = 0; i < hexString.length; i += 2) {
        byteArray[i / 2] = parseInt(hexString.substr(i, 2), 16);
    }
    return byteArray;
}

function bytesToString(bytes) {
    return Array.from(bytes).map(byte => byte.toString()).join('-');
}

async function calcTOTPSlot(slotBytes,
                            TOTPLength,
                            alphabet,
                            sharedSecret) {

    // JavaScript's Buffer methods default to big-endian!
    if (!isLittleEndian())
        reverseBytes(slotBytes);

    const hash = await crypto.subtle.sign(
        "HMAC",
        await crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(sharedSecret),
            {
                name: "HMAC",
                hash: "SHA-256"
            },
            false,
            ["sign", "verify"]
        ),
        slotBytes
    );

    const currentHash = new Uint8Array(hash);
    const offset      = currentHash[currentHash.length - 1] & 0x0F;

    let result = '';
    for (let i = 0; i < TOTPLength; i++)
        result += alphabet[(currentHash[(offset + i) % currentHash.length] >>> 0) % alphabet.length];

    return result;

}

export async function generateTOTPs(SharedSecret,
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

    var  currentUnixTime     = 0;

    if (typeof Timestamp === 'string')
        currentUnixTime = Math.floor(new Date(Timestamp).getTime() / 1000) - new Date().getTimezoneOffset() * 60;
    else if (typeof Timestamp === 'number')
        currentUnixTime = Timestamp;
    else
        throw new Error('Invalid timestamp format');

    const currentSlot        = BigInt(Math.floor(currentUnixTime / ValidityTime));
    const remainingTime      = ValidityTime - (currentUnixTime % ValidityTime);

    // For interoperability we use 8 byte timestamps
    const previousSlotBytes  = new Uint8Array(8);
    const currentSlotBytes   = new Uint8Array(8);
    const nextSlotBytes      = new Uint8Array(8);

    new DataView(previousSlotBytes.buffer).setBigUint64(0, currentSlot - BigInt(1));
    new DataView(currentSlotBytes.buffer). setBigUint64(0, currentSlot);
    new DataView(nextSlotBytes.buffer).    setBigUint64(0, currentSlot + BigInt(1));

    const previous           = await calcTOTPSlot(previousSlotBytes, TOTPLength, Alphabet, SharedSecret);
    const current            = await calcTOTPSlot(currentSlotBytes,  TOTPLength, Alphabet, SharedSecret);
    const next               = await calcTOTPSlot(nextSlotBytes,     TOTPLength, Alphabet, SharedSecret);

    return {
        previous,
        current,
        next,
        remainingTime
    };

}