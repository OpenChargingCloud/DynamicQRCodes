const crypto = require('crypto');

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

    console.log(`Slot bytes: ${bytesToString(slotBytes)}`);

    const hmac        = crypto.createHmac('sha256', Buffer.from(sharedSecret, 'utf-8'));
    const currentHash = hmac.update(slotBytes).digest();
    const offset      = currentHash[currentHash.length - 1] & 0x0F;

    let result = '';
    for (let i = 0; i < TOTPLength; i++)
        result += alphabet[currentHash[(offset + i) % currentHash.length] % alphabet.length];

    return result;

}


function generateTOTPs(sharedSecret, validityTime = 30, TOTPLength = 12, alphabet = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') {

    sharedSecret = sharedSecret.trim();
    alphabet     = alphabet.trim();

    if (!sharedSecret)                              throw new Error("The given shared secret must not be null or empty!");
    if (/\s/.test(sharedSecret))                    throw new Error("The given shared secret must not contain any whitespace character!");
    if (sharedSecret.length < 16)                   throw new Error("The length of the given shared secret must be at least 16 characters!");
    if (TOTPLength < 4)                             throw new Error("The expected length of the TOTP must be between 4 and 255 characters!");
    if (!alphabet)                                  throw new Error("The given alphabet must not be null or empty!");
    if (alphabet.length < 4)                        throw new Error("The given alphabet must contain at least 4 characters!");
    if (new Set(alphabet).size !== alphabet.length) throw new Error("The given alphabet must not contain duplicate characters!");
    if (/\s/.test(alphabet))                        throw new Error("The given alphabet must not contain any whitespace character!");

    const currentUnixTime    = Math.floor(Date.now() / 1000);
    const currentSlot        = BigInt(Math.floor(currentUnixTime / validityTime));
    const remainingTime      = validityTime - (currentUnixTime % validityTime);

    // For interoperability we use 8 byte timestamps
    const previousSlotBytes  = Buffer.alloc(8);
    const currentSlotBytes   = Buffer.alloc(8);
    const nextSlotBytes      = Buffer.alloc(8);

    previousSlotBytes.writeBigUInt64BE(currentSlot - BigInt(1));
    currentSlotBytes. writeBigUInt64BE(currentSlot);
    nextSlotBytes.    writeBigUInt64BE(currentSlot + BigInt(1));

    const previousTOTP       = calcTOTPSlot(previousSlotBytes, TOTPLength, alphabet, sharedSecret);
    const currentTOTP        = calcTOTPSlot(currentSlotBytes,  TOTPLength, alphabet, sharedSecret);
    const nextTOTP           = calcTOTPSlot(nextSlotBytes,     TOTPLength, alphabet, sharedSecret);

    return {
        previousTOTP,
        currentTOTP,
        nextTOTP,
        remainingTime: remainingTime * 1000 // Convert to milliseconds
    };

}

// Example usage
const { previousTOTP, currentTOTP, nextTOTP, remainingTime } = generateTOTPs('secure!Charging!');
console.log(`Generated TOTP: (${previousTOTP}, ${currentTOTP}, ${nextTOTP}, ${remainingTime} milliseconds)`);
