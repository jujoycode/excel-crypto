import { createHash, createHmac } from 'crypto'

export class CryptoUtil {
  // Create HMAC
  public hmac(algorithm: string, key: Buffer, ...buffers: Array<Buffer>): Buffer {
    const hmac = createHmac(algorithm.toLowerCase(), key)
    hmac.update(Buffer.concat(buffers))

    return hmac.digest();
  }

  // Create IV for HMAC
  public createIV(hashAlgorithm: string, salt: Buffer, blockSize: number, blockKey: Buffer | number): Buffer {
    // Create the block key from the current index
    if (typeof blockKey === 'number') {
      blockKey = this.createUInt32LEBuffer(blockKey)
    }

    // Create the initialization vector by hashing the salt with the block key.
    // Truncate or pad as needed to meet the block size.
    let iv = this.hash(hashAlgorithm, salt, blockKey);

    if (iv.length < blockSize) {
      const tmp = Buffer.alloc(blockSize, 0x36);
      iv.copy(tmp);
      iv = tmp;
    } else if (iv.length > blockSize) {
      iv = iv.subarray(0, blockSize);
    }

    return iv;
  }

  // Create Unit32Buffer
  public createUInt32LEBuffer(value: number, bufferSize: number | undefined = 4): Buffer {
    const buffer = Buffer.alloc(bufferSize)
    buffer.writeUInt32LE(value, 0)

    return buffer
  }

  // Create hash
  public hash(algorithm: string, ...buffers: any[]): Buffer {
    const hash = createHash(algorithm)
    hash.update(Buffer.concat(buffers))

    return hash.digest()
  }
}