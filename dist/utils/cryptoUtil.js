"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CryptoUtil = void 0;
const crypto_1 = require("crypto");
class CryptoUtil {
    // Create HMAC
    hmac(algorithm, key, ...buffers) {
        const hmac = (0, crypto_1.createHmac)(algorithm.toLowerCase(), key);
        hmac.update(Buffer.concat(buffers));
        return hmac.digest();
    }
    // Create IV for HMAC
    createIV(hashAlgorithm, salt, blockSize, blockKey) {
        // Create the block key from the current index
        if (typeof blockKey === 'number') {
            blockKey = this.createUInt32LEBuffer(blockKey);
        }
        // Create the initialization vector by hashing the salt with the block key.
        // Truncate or pad as needed to meet the block size.
        let iv = this.hash(hashAlgorithm, salt, blockKey);
        if (iv.length < blockSize) {
            const tmp = Buffer.alloc(blockSize, 0x36);
            iv.copy(tmp);
            iv = tmp;
        }
        else if (iv.length > blockSize) {
            iv = iv.subarray(0, blockSize);
        }
        return iv;
    }
    // Create Unit32Buffer
    createUInt32LEBuffer(value, bufferSize = 4) {
        const buffer = Buffer.alloc(bufferSize);
        buffer.writeUInt32LE(value, 0);
        return buffer;
    }
    // Create hash
    hash(algorithm, ...buffers) {
        const hash = (0, crypto_1.createHash)(algorithm);
        hash.update(Buffer.concat(buffers));
        return hash.digest();
    }
}
exports.CryptoUtil = CryptoUtil;
