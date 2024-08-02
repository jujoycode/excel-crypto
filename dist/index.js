"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.XLSX_Encryptor = void 0;
const crypto_1 = require("crypto");
const cfb_1 = require("cfb");
const cryptoUtil_1 = require("./utils/cryptoUtil");
const xmlUtil_1 = require("./utils/xmlUtil");
/**
 * ECMA376_Encryptor
 * @desc ECMA 376 형식에 맞춘 xlsx 파일의 암호화 지원
 * @link [MS Office File Format](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/cab78f5c-9c17-495e-bea9-032c63f02ad8)
 * @link [ECMA-376](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
*/
class XLSX_Encryptor {
    constructor() {
        this.packageKey = (0, crypto_1.randomBytes)(32);
        this.encPrefix = Buffer.from([0x04, 0x00, 0x04, 0x00, 0x40, 0x00, 0x00, 0x00]);
        this.iChunkSize = 4096;
        this.iOffset = 8;
        this.objBlockKey = {
            key: Buffer.from([0x14, 0x6e, 0x0b, 0xe7, 0xab, 0xac, 0xd0, 0xd6]),
            integrity: {
                hmacKey: Buffer.from([0x5f, 0xb2, 0xad, 0x01, 0x0c, 0xb9, 0xe1, 0xf6]),
                hmacValue: Buffer.from([0xa0, 0x67, 0x7f, 0x02, 0xb2, 0x2c, 0x84, 0x33]),
            },
            verifierHash: {
                input: Buffer.from([0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79]),
                value: Buffer.from([0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e]),
            }
        };
        this.objEncInfo = {
            package: {
                cipherAlgorithm: 'AES', // 사용할 암호화 알고리즘
                cipherChaining: 'ChainingModeCBC', // 암호화 체인 모드
                salt: (0, crypto_1.randomBytes)(16), // 솔트 값 생성
                hashAlgorithm: 'SHA512', // 해시 알고리즘
                hashSize: 64, // 해시 크기
                blockSize: 16, // 블록 크기
                keyBits: this.packageKey.length * 8, // 키 비트 수
            },
            key: {
                cipherAlgorithm: 'AES',
                cipherChaining: 'ChainingModeCBC',
                salt: (0, crypto_1.randomBytes)(16),
                hashAlgorithm: 'SHA512',
                hashSize: 64,
                blockSize: 16,
                spinCount: 100000, // 해시 반복 횟수
                keyBits: 256, // 암호화 키는 최대 255자
                encryptedKeyValue: undefined,
                encryptedVerifierHashInput: undefined,
                encryptedVerifierHashValue: undefined,
            },
            dataIntegrity: {
                encryptedHmacKey: undefined,
                encryptedHmacValue: undefined
            }
        };
        this.cryptoTool = new cryptoUtil_1.CryptoUtil();
        this.xmlTool = new xmlUtil_1.XmlUtil();
    }
    // Data Encrypt
    encrypt(data, password) {
        // 2. Package 암호화
        const encryptedPackage = this.cryptPackage('encrypt', this.objEncInfo.package.cipherAlgorithm, this.objEncInfo.package.cipherChaining, this.objEncInfo.package.hashAlgorithm, this.objEncInfo.package.blockSize, this.objEncInfo.package.salt, this.packageKey, data);
        // 3. 데이터 무결성 생성
        // HMAC 키 생성
        const hmacKey = (0, crypto_1.randomBytes)(64);
        // HMAC 키를 암호화하기 위한 초기화 벡터 생성
        const hmacKeyIV = this.cryptoTool.createIV(this.objEncInfo.package.hashAlgorithm, this.objEncInfo.package.salt, this.objEncInfo.package.blockSize, this.objBlockKey.integrity.hmacKey);
        // HMAC 키 암호화 실행
        const encryptedHmacKey = this.crypt('encrypt', // 암호화 모드 설정
        this.objEncInfo.package.cipherAlgorithm, this.objEncInfo.package.cipherChaining, this.packageKey, hmacKeyIV, hmacKey);
        // 암호화된 패키지에 대한 HMAC 값 계산
        const hmacValue = this.cryptoTool.hmac(this.objEncInfo.package.hashAlgorithm, hmacKey, encryptedPackage);
        // HMAC 값 암호화를 위한 초기화 벡터 생성
        const hmacValueIV = this.cryptoTool.createIV(this.objEncInfo.package.hashAlgorithm, this.objEncInfo.package.salt, this.objEncInfo.package.blockSize, this.objBlockKey.integrity.hmacValue);
        // HMAC 값 암호화 실행
        const encryptedHmacValue = this.crypt('encrypt', // 암호화 모드 설정
        this.objEncInfo.package.cipherAlgorithm, this.objEncInfo.package.cipherChaining, this.packageKey, hmacValueIV, hmacValue);
        // 암호화 정보 객체에 데이터 무결성 정보 저장
        this.objEncInfo.dataIntegrity = {
            encryptedHmacKey,
            encryptedHmacValue,
        };
        // 패스워드를 이용한 키 생성
        const key = this.convertPasswordToKey(password, this.objEncInfo.key.hashAlgorithm, this.objEncInfo.key.salt, this.objEncInfo.key.spinCount, this.objEncInfo.key.keyBits, this.objBlockKey.key);
        // 패키지 키 암호화
        this.objEncInfo.key.encryptedKeyValue = this.crypt('encrypt', // 암호화 모드 설정
        this.objEncInfo.key.cipherAlgorithm, this.objEncInfo.key.cipherChaining, key, this.objEncInfo.key.salt, this.packageKey);
        // 검증 해시 입력 값 생성
        const verifierHashInput = (0, crypto_1.randomBytes)(16);
        // 검증 해시 입력 값에 대한 암호화 키 생성
        const verifierHashInputKey = this.convertPasswordToKey(password, this.objEncInfo.key.hashAlgorithm, this.objEncInfo.key.salt, this.objEncInfo.key.spinCount, this.objEncInfo.key.keyBits, this.objBlockKey.verifierHash.input);
        // 검증 해시 입력 값 암호화
        this.objEncInfo.key.encryptedVerifierHashInput = this.crypt('encrypt', // 암호화 모드 설정
        this.objEncInfo.key.cipherAlgorithm, this.objEncInfo.key.cipherChaining, verifierHashInputKey, this.objEncInfo.key.salt, verifierHashInput);
        // 검증 해시 값 계산
        const verifierHashValue = this.cryptoTool.hash(this.objEncInfo.key.hashAlgorithm, verifierHashInput);
        // 검증 해시 값에 대한 암호화 키 생성
        const verifierHashValueKey = this.convertPasswordToKey(password, this.objEncInfo.key.hashAlgorithm, this.objEncInfo.key.salt, this.objEncInfo.key.spinCount, this.objEncInfo.key.keyBits, this.objBlockKey.verifierHash.value);
        // 검증 해시 값 암호화
        this.objEncInfo.key.encryptedVerifierHashValue = this.crypt('encrypt', // 암호화 모드 설정
        this.objEncInfo.key.cipherAlgorithm, this.objEncInfo.key.cipherChaining, verifierHashValueKey, this.objEncInfo.key.salt, verifierHashValue);
        // 암호화 정보 XML 생성
        const encryptionInfoXml = this.xmlTool.createEncXml(this.objEncInfo.package, this.objEncInfo.key, this.objEncInfo.dataIntegrity);
        // 암호화 정보 XML과 Prefix를 결합하여 Buffer 생성
        const encryptionInfoBuffer = Buffer.concat([this.encPrefix, Buffer.from(encryptionInfoXml, 'utf8')]);
        // 새 CFB 컨테이너 생성
        let output = cfb_1.utils.cfb_new();
        // 컨테이너에 암호화 정보 및 암호화된 패키지 추가
        cfb_1.utils.cfb_add(output, 'EncryptionInfo', encryptionInfoBuffer);
        cfb_1.utils.cfb_add(output, 'EncryptedPackage', encryptedPackage);
        // 불필요한 파일 삭제
        cfb_1.utils.cfb_del(output, '\u0001Sh33tJ5');
        // 컨테이너를 파일로 쓰기
        const result = (0, cfb_1.write)(output);
        // 결과가 Buffer가 아닐 경우 Buffer로 변환
        if (!Buffer.isBuffer(result)) {
            return Buffer.from(result);
        }
        // 최종 결과 반환
        return result;
    }
    // Data Enrypt / Decrypt
    crypt(type, cipherAlgorithm, cipherChaining, key, iv, input) {
        let algorithm = `${cipherAlgorithm.toLowerCase()}-${key.length * 8}`;
        if (cipherChaining === 'ChainingModeCBC') {
            algorithm += '-cbc';
        }
        else {
            throw new Error(`Unknown cipher chaining: ${cipherChaining}`);
        }
        const cipher = type === 'encrypt' ? (0, crypto_1.createCipheriv)(algorithm, key, iv) : (0, crypto_1.createDecipheriv)(algorithm, key, iv);
        cipher.setAutoPadding(false);
        let output = cipher.update(input);
        output = Buffer.concat([output, cipher.final()]);
        return output;
    }
    // Package Encrypt / Decrypt
    cryptPackage(encrypt, cipherAlgorithm, cipherChaining, hashAlgorithm, blockSize, salt, key, input) {
        const outputChunks = [];
        const offset = encrypt ? 0 : this.iOffset;
        // The package is encoded in chunks. Encrypt/decrypt each and concat.
        let i = 0;
        let start = 0;
        let end = 0;
        while (end < input.length) {
            start = end;
            end = start + this.iChunkSize;
            if (end > input.length)
                end = input.length;
            // Grab the next chunk using subarray instead of slice
            let inputChunk = input.subarray(start + offset, end + offset);
            // Pad the chunk if it is not an integer multiple of the block size
            const remainder = inputChunk.length % blockSize;
            if (remainder)
                inputChunk = Buffer.concat([inputChunk, Buffer.alloc(blockSize - remainder)]);
            // Create the initialization vector
            const iv = this.cryptoTool.createIV(hashAlgorithm, salt, blockSize, i);
            // Encrypt/decrypt the chunk and add it to the array
            const outputChunk = this.crypt(encrypt, cipherAlgorithm, cipherChaining, key, iv, inputChunk);
            outputChunks.push(outputChunk);
            i++;
        }
        // Concat all of the output chunks.
        let output = Buffer.concat(outputChunks);
        if (encrypt) {
            // Put the length of the package in the first 8 bytes
            output = Buffer.concat([this.cryptoTool.createUInt32LEBuffer(input.length, this.iOffset), output]);
        }
        else {
            // Truncate the buffer to the size in the prefix using subarray
            const length = input.readUInt32LE(0);
            output = output.subarray(0, length);
        }
        return output;
    }
    // Convert a password into an encryption key
    convertPasswordToKey(password, hashAlgorithm, salt, spinCount, keyBits, blockKey) {
        // Password must be in unicode buffer
        const passwordBuffer = Buffer.from(password, 'utf16le');
        // Generate the initial hash
        let key = this.cryptoTool.hash(hashAlgorithm, salt, passwordBuffer);
        // Now regenerate until spin count
        for (let i = 0; i < spinCount; i++) {
            const iterator = this.cryptoTool.createUInt32LEBuffer(i);
            key = this.cryptoTool.hash(hashAlgorithm, iterator, key);
        }
        // Now generate the final hash
        key = this.cryptoTool.hash(hashAlgorithm, key, blockKey);
        // Truncate or pad as needed to get to length of keyBits
        const keyBytes = keyBits / 8;
        if (key.length < keyBytes) {
            const tmp = Buffer.alloc(keyBytes, 0x36);
            key.copy(tmp);
            key = tmp;
        }
        else if (key.length > keyBytes) {
            key = key.subarray(0, keyBytes);
        }
        return key;
    }
}
exports.XLSX_Encryptor = XLSX_Encryptor;
