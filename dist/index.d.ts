/**
 * ECMA376_Encryptor
 * @desc ECMA 376 형식에 맞춘 xlsx 파일의 암호화 지원
 * @link [MS Office File Format](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/cab78f5c-9c17-495e-bea9-032c63f02ad8)
 * @link [ECMA-376](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
*/
export declare class XLSX_Encryptor {
    private cryptoTool;
    private xmlTool;
    private packageKey;
    private encPrefix;
    private iChunkSize;
    private iOffset;
    private objBlockKey;
    private objEncInfo;
    constructor();
    encrypt(data: Buffer, password: string): Buffer;
    private crypt;
    private cryptPackage;
    private convertPasswordToKey;
}
