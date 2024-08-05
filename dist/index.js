"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.XLSX_Cryptor = void 0;
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
class XLSX_Cryptor {
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
    /**
    * @desc 주어진 데이터와 비밀번호를 사용하여 xlsx 파일을 암호화합니다.
    * @example
    * const xlsxFile = readFileSync('./xlsxFile.xlsx')
    * const encryptXlsx = new XLSX_Cryptor().encrypt({data: xlsxFile, password: 'P@ssw0rd1!'})
    */
    encrypt({ data, password }) {
        // 0. CFB Container 생성
        const cfbContainer = cfb_1.utils.cfb_new();
        // 1. Package 암호화
        const encryptedPackage = this.createEncryptedPackage(data);
        cfb_1.utils.cfb_add(cfbContainer, 'EncryptedPackage', encryptedPackage);
        // 2. key 관련 정보 생성
        const verifierHashInput = (0, crypto_1.randomBytes)(16);
        this.objEncInfo.key.encryptedVerifierHashInput = this.createEncryptedVerifierHashInput(password, verifierHashInput);
        this.objEncInfo.key.encryptedVerifierHashValue = this.createEncryptedVerifierHashValue(password, verifierHashInput);
        this.objEncInfo.key.encryptedKeyValue = this.createEncryptedKeyValue(password);
        // 3. 무결성 정보 생성
        const hmacKey = (0, crypto_1.randomBytes)(64);
        this.objEncInfo.dataIntegrity = {
            encryptedHmacKey: this.createEncryptedHmacKey(hmacKey),
            encryptedHmacValue: this.createEncryptedHmacValue(hmacKey, encryptedPackage),
        };
        // 4. 암호화 xml 생성
        const encryptionInfoXml = this.xmlTool.createEncXml(this.objEncInfo.package, this.objEncInfo.key, this.objEncInfo.dataIntegrity);
        // 5. Buffer로 변환 후 컨테이너에 추가
        const encryptionInfoBuffer = Buffer.concat([this.encPrefix, Buffer.from(encryptionInfoXml, 'utf8')]);
        cfb_1.utils.cfb_add(cfbContainer, 'EncryptionInfo', encryptionInfoBuffer);
        // Delete the SheetJS entry that is added at initialization
        // utils.cfb_del(cfbContainer, '\u0001Sh33tJ5')
        // 6. 결과 반환
        const result = (0, cfb_1.write)(cfbContainer);
        return Buffer.isBuffer(result) ? result : Buffer.from(result);
    }
    /**
     * @param type 암복호화 여부
     * @param cipherAlgorithm 사용할 암호 알고리즘
     * @param cipherChaining 사용할 암호 연쇄 모드 ('ChainingModeCBC')
     * @param key 암호화에 사용할 키
     * @param iv 초기화 벡터
     * @param input 암호화 또는 복호화할 데이터
     * @desc 주어진 암호화 알고리즘과 연쇄 모드, 키, 초기화 벡터를 사용하여 데이터를 암호화하거나 복호화합니다.
     */
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
    /**
    * @param encrypt 암복호화 여부
    * @param cipherAlgorithm 사용할 암호 알고리즘
    * @param cipherChaining 사용할 암호 연쇄 모드
    * @param hashAlgorithm 사용할 해시 알고리즘
    * @param blockSize 블록 크기
    * @param salt
    * @param key 암호화에 사용할 키
    * @param input 암호화 또는 복호화할 데이터
    * @desc 주어진 데이터를 블록 단위로 암호화하거나 복호화
    *       각 블록에 대해 초기화 벡터를 생성하고, 블록 단위로 데이터를 암호화 또는 복호화
    */
    cryptPackage(type, cipherAlgorithm, cipherChaining, hashAlgorithm, blockSize, salt, key, input) {
        const outputChunks = [];
        const offset = type === 'encrypt' ? 0 : this.iOffset;
        // 패키지는 청크 단위로 인코딩, 각 청크를 암호화/복호화 후 연결
        let i = 0;
        let start = 0;
        let end = 0;
        while (end < input.length) {
            start = end;
            end = start + this.iChunkSize;
            if (end > input.length)
                end = input.length;
            // 다음 청크 획득
            let inputChunk = input.subarray(start + offset, end + offset);
            // 블록 크기의 정수 배수가 아닐 경우 청크 패딩
            const remainder = inputChunk.length % blockSize;
            if (remainder)
                inputChunk = Buffer.concat([inputChunk, Buffer.alloc(blockSize - remainder)]);
            // 초기화 벡터 생성
            const iv = this.cryptoTool.createIV(hashAlgorithm, salt, blockSize, i);
            // 청크 암호화/복호화 후 대상 추가
            const outputChunk = this.crypt(type, cipherAlgorithm, cipherChaining, key, iv, inputChunk);
            outputChunks.push(outputChunk);
            i++;
        }
        // 모든 출력 청크를 연결합니다.
        let output = Buffer.concat(outputChunks);
        if (type === 'encrypt') {
            output = Buffer.concat([this.cryptoTool.createUInt32LEBuffer(input.length, this.iOffset), output]);
        }
        else {
            const length = input.readUInt32LE(0);
            output = output.subarray(0, length);
        }
        return output;
    }
    /**
    * @param password 사용자 입력 비밀번호
    * @param hashAlgorithm 사용할 해시 알고리즘
    * @param salt
    * @param spinCount 해시 재생성 횟수
    * @param keyBits 키의 비트 길이
    * @param blockKey 블록 키
    * @desc 주어진 비밀번호를 사용하여 암호화 키를 생성
    *       초기 해시를 생성 후 spinCount 횟수만큼 재생성
    */
    convertPasswordToKey(password, hashAlgorithm, salt, spinCount, keyBits, blockKey) {
        // 비밀번호를 유니코드 버퍼로 변환
        const passwordBuffer = Buffer.from(password, 'utf16le');
        // 초기 해시를 생성
        let key = this.cryptoTool.hash(hashAlgorithm, salt, passwordBuffer);
        // spinCount 횟수만큼 재생성
        for (let i = 0; i < spinCount; i++) {
            const iterator = this.cryptoTool.createUInt32LEBuffer(i);
            key = this.cryptoTool.hash(hashAlgorithm, iterator, key);
        }
        // 최종 해시를 생성
        key = this.cryptoTool.hash(hashAlgorithm, key, blockKey);
        // keyBits 길이에 맞게 키를 자르거나 패딩
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
    createEncryptedPackage(data) {
        return this.cryptPackage('encrypt', this.objEncInfo.package.cipherAlgorithm, this.objEncInfo.package.cipherChaining, this.objEncInfo.package.hashAlgorithm, this.objEncInfo.package.blockSize, this.objEncInfo.package.salt, this.packageKey, data);
    }
    createEncryptedHmacKey(hmacKey) {
        const hmacKeyIV = this.cryptoTool.createIV(this.objEncInfo.package.hashAlgorithm, this.objEncInfo.package.salt, this.objEncInfo.package.blockSize, this.objBlockKey.integrity.hmacKey);
        return this.crypt('encrypt', this.objEncInfo.package.cipherAlgorithm, this.objEncInfo.package.cipherChaining, this.packageKey, hmacKeyIV, hmacKey);
    }
    createEncryptedHmacValue(hmacKey, encryptedPackage) {
        const hmacValue = this.cryptoTool.hmac(this.objEncInfo.package.hashAlgorithm, hmacKey, encryptedPackage);
        const hmacValueIV = this.cryptoTool.createIV(this.objEncInfo.package.hashAlgorithm, this.objEncInfo.package.salt, this.objEncInfo.package.blockSize, this.objBlockKey.integrity.hmacValue);
        return this.crypt('encrypt', this.objEncInfo.package.cipherAlgorithm, this.objEncInfo.package.cipherChaining, this.packageKey, hmacValueIV, hmacValue);
    }
    createEncryptedKeyValue(password) {
        const key = this.convertPasswordToKey(password, this.objEncInfo.key.hashAlgorithm, this.objEncInfo.key.salt, this.objEncInfo.key.spinCount, this.objEncInfo.key.keyBits, this.objBlockKey.key);
        return this.crypt('encrypt', this.objEncInfo.key.cipherAlgorithm, this.objEncInfo.key.cipherChaining, key, this.objEncInfo.key.salt, this.packageKey);
    }
    createEncryptedVerifierHashInput(password, verifierHashInput) {
        const verifierHashInputKey = this.convertPasswordToKey(password, this.objEncInfo.key.hashAlgorithm, this.objEncInfo.key.salt, this.objEncInfo.key.spinCount, this.objEncInfo.key.keyBits, this.objBlockKey.verifierHash.input);
        return this.crypt('encrypt', this.objEncInfo.key.cipherAlgorithm, this.objEncInfo.key.cipherChaining, verifierHashInputKey, this.objEncInfo.key.salt, verifierHashInput);
    }
    createEncryptedVerifierHashValue(password, verifierHashInput) {
        const verifierHashValueKey = this.convertPasswordToKey(password, this.objEncInfo.key.hashAlgorithm, this.objEncInfo.key.salt, this.objEncInfo.key.spinCount, this.objEncInfo.key.keyBits, this.objBlockKey.verifierHash.value);
        return this.crypt('encrypt', this.objEncInfo.key.cipherAlgorithm, this.objEncInfo.key.cipherChaining, verifierHashValueKey, this.objEncInfo.key.salt, this.cryptoTool.hash(this.objEncInfo.key.hashAlgorithm, verifierHashInput));
    }
}
exports.XLSX_Cryptor = XLSX_Cryptor;
