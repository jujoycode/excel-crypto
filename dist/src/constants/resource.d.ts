declare const ENC_PREFIX: Buffer;
declare const BLOCK_KEY: {
    KEY: Buffer;
    INTEGRITY: {
        HMAC_KEY: Buffer;
        HMAC_VALUE: Buffer;
    };
    VERIFIER_HASH: {
        INPUT: Buffer;
        VALUE: Buffer;
    };
};
declare const VERSION: Buffer;
declare const PRIMARY: Buffer;
declare const DATASPACE_MAP: Buffer;
declare const STRONT_ENCRYPTION_DATASPACE: Buffer;
export { ENC_PREFIX, BLOCK_KEY, VERSION, PRIMARY, DATASPACE_MAP, STRONT_ENCRYPTION_DATASPACE };
