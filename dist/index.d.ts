/**
 * ECMA376_Encryptor
 * @desc ECMA 376 형식에 맞춘 xlsx 파일의 암호화 지원
 * @link [MS Office File Format](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/cab78f5c-9c17-495e-bea9-032c63f02ad8)
 * @link [ECMA-376](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
*/
export declare class XLSX_Cryptor {
    private cryptoTool;
    private xmlTool;
    private packageKey;
    private encPrefix;
    private iChunkSize;
    private iOffset;
    private objBlockKey;
    private objEncInfo;
    constructor();
    /**
    * @desc 주어진 데이터와 비밀번호를 사용하여 xlsx 파일을 암호화합니다.
    * @example
    * const xlsxFile = readFileSync('./xlsxFile.xlsx')
    * const encryptXlsx = new XLSX_Cryptor().encrypt({data: xlsxFile, password: 'P@ssw0rd1!'})
    */
    encrypt({ data, password }: {
        data: Buffer;
        password: string;
    }): Buffer;
    /**
     * @param type 암복호화 여부
     * @param cipherAlgorithm 사용할 암호 알고리즘
     * @param cipherChaining 사용할 암호 연쇄 모드 ('ChainingModeCBC')
     * @param key 암호화에 사용할 키
     * @param iv 초기화 벡터
     * @param input 암호화 또는 복호화할 데이터
     * @desc 주어진 암호화 알고리즘과 연쇄 모드, 키, 초기화 벡터를 사용하여 데이터를 암호화하거나 복호화합니다.
     */
    private crypt;
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
    private cryptPackage;
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
    private convertPasswordToKey;
    private createEncryptedPackage;
    private createEncryptedHmacKey;
    private createEncryptedHmacValue;
    private createEncryptedKeyValue;
    private createEncryptedVerifierHashInput;
    private createEncryptedVerifierHashValue;
}
