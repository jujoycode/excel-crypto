export declare class CryptoUtil {
    hmac(algorithm: string, key: Buffer, ...buffers: Array<Buffer>): Buffer;
    createIV(hashAlgorithm: string, salt: Buffer, blockSize: number, blockKey: Buffer | number): Buffer;
    createUInt32LEBuffer(value: number, bufferSize?: number | undefined): Buffer;
    hash(algorithm: string, ...buffers: any[]): Buffer;
}
