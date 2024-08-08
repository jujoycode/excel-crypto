import { randomBytes, createCipheriv, createDecipheriv } from 'crypto'
import { utils, write as cfb_write } from 'cfb'

import { CryptoUtil } from './utils/cryptoUtil'
import { XmlUtil } from './utils/xmlUtil'
import {
  ENC_PREFIX,
  BLOCK_KEY,
  VERSION,
  PRIMARY,
  DATASPACE_MAP,
  STRONG_ENCRYPTION_DATASPACE
} from './constants/resource'

/**
 * ECMA376_Encryptor
 * @desc ECMA 376 형식에 맞춘 xlsx 파일의 암호화 지원
 * @link [MS Office File Format](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/cab78f5c-9c17-495e-bea9-032c63f02ad8)
 * @link [ECMA-376](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
 * @link 참고1. [xlsx-populate](https://www.npmjs.com/package/xlsx-populate)
 * @link 참고2. [officecrypto-tool](https://www.npmjs.com/package/officecrypto-tool)
*/
export class XLSX_Cryptor {
  private cryptoTool: CryptoUtil
  private xmlTool: XmlUtil

  private packageKey = randomBytes(32)
  private iChunkSize = 4096
  private iOffset = 8

  private objEncInfo = {
    package: {
      cipherAlgorithm: 'AES',
      cipherChaining: 'ChainingModeCBC',
      salt: randomBytes(16),
      hashAlgorithm: 'SHA512',
      hashSize: 64,
      blockSize: 16,
      keyBits: this.packageKey.length * 8,
    },
    key: {
      cipherAlgorithm: 'AES',
      cipherChaining: 'ChainingModeCBC',
      salt: randomBytes(16),
      hashAlgorithm: 'SHA512',
      hashSize: 64,
      blockSize: 16,
      spinCount: 500,
      keyBits: 256,
      encryptedKeyValue: undefined,
      encryptedVerifierHashInput: undefined,
      encryptedVerifierHashValue: undefined,
    },
    dataIntegrity: {
      encryptedHmacKey: undefined,
      encryptedHmacValue: undefined
    }
  }

  constructor() {
    this.cryptoTool = new CryptoUtil()
    this.xmlTool = new XmlUtil()
  }

  /**
  * @desc 주어진 데이터와 비밀번호를 사용하여 xlsx 파일을 암호화합니다.
  * @example
  * const xlsxFile = readFileSync('./xlsxFile.xlsx')
  * const encryptXlsx = new XLSX_Cryptor().encrypt({data: xlsxFile, password: 'P@ssw0rd1!'})
  */
  public encrypt({ data, password }: { data: Buffer, password: string }): Buffer {
    // 0. CFB Container 생성
    const cfbContainer = utils.cfb_new()

    // 1. Package 암호화
    const encryptedPackage = this.createEncryptedPackage(data)
    utils.cfb_add(cfbContainer, 'EncryptedPackage', encryptedPackage)

    // 2. key 관련 정보 생성
    const verifierHashInput = randomBytes(16)

    this.objEncInfo.key.encryptedVerifierHashInput = this.createEncryptedVerifierHashInput(password, verifierHashInput)
    this.objEncInfo.key.encryptedVerifierHashValue = this.createEncryptedVerifierHashValue(password, verifierHashInput)
    this.objEncInfo.key.encryptedKeyValue = this.createEncryptedKeyValue(password)

    // 3. 무결성 정보 생성
    const hmacKey = randomBytes(64)

    this.objEncInfo.dataIntegrity = {
      encryptedHmacKey: this.createEncryptedHmacKey(hmacKey),
      encryptedHmacValue: this.createEncryptedHmacValue(hmacKey, encryptedPackage),
    }

    // 4. 암호화 xml 생성
    const encryptionInfoXml = this.xmlTool.createEncXml(this.objEncInfo.package, this.objEncInfo.key, this.objEncInfo.dataIntegrity)

    // 5. Buffer로 변환 후 컨테이너에 추가
    const encryptionInfoBuffer = Buffer.concat([ENC_PREFIX, Buffer.from(encryptionInfoXml, 'utf8')])
    utils.cfb_add(cfbContainer, 'EncryptionInfo', encryptionInfoBuffer)

    // 5-1. _DataSpace 생성
    utils.cfb_add(cfbContainer, '\x06DataSpaces/', null)

    utils.cfb_add(cfbContainer, '\x06DataSpaces/DataSpaceMap', DATASPACE_MAP)
    utils.cfb_add(cfbContainer, '\x06DataSpaces/Version', VERSION)
    utils.cfb_add(cfbContainer, '\x06DataSpaces/DataSpaceInfo/StrongEncryptionDataSpace', STRONG_ENCRYPTION_DATASPACE)
    utils.cfb_add(cfbContainer, '\x06DataSpaces/TransformInfo/StrongEncryptionTransform/\x06Primary', PRIMARY)

    // 6. 결과 반환
    const result = cfb_write(cfbContainer)
    return Buffer.isBuffer(result) ? result : Buffer.from(result)
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
  private crypt(type: 'encrypt' | 'decrypt', cipherAlgorithm: string, cipherChaining: string, key: Buffer, iv: Buffer, input: Buffer): Buffer {
    let algorithm = `${cipherAlgorithm.toLowerCase()}-${key.length * 8}`

    if (cipherChaining === 'ChainingModeCBC') {
      algorithm += '-cbc'
    } else {
      throw new Error(`Unknown cipher chaining: ${cipherChaining}`)
    }

    const cipher = type === 'encrypt' ? createCipheriv(algorithm, key, iv) : createDecipheriv(algorithm, key, iv)
    cipher.setAutoPadding(false)

    let output = cipher.update(input)
    output = Buffer.concat([output, cipher.final()])

    return output
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
  private cryptPackage(type: 'encrypt' | 'decrypt', cipherAlgorithm: string, cipherChaining: string, hashAlgorithm: string, blockSize: number, salt: Buffer, key: Buffer, input: Buffer): Buffer {
    const outputChunks = []
    const offset = type === 'encrypt' ? 0 : this.iOffset

    // 패키지는 청크 단위로 인코딩, 각 청크를 암호화/복호화 후 연결
    let i = 0
    let start = 0
    let end = 0
    while (end < input.length) {
      start = end
      end = start + this.iChunkSize
      if (end > input.length) end = input.length

      // 다음 청크 획득
      let inputChunk = input.subarray(start + offset, end + offset)

      // 블록 크기의 정수 배수가 아닐 경우 청크 패딩
      const remainder = inputChunk.length % blockSize
      if (remainder) inputChunk = Buffer.concat([inputChunk, Buffer.alloc(blockSize - remainder)])

      // 초기화 벡터 생성
      const iv = this.cryptoTool.createIV(hashAlgorithm, salt, blockSize, i)

      // 청크 암호화/복호화 후 대상 추가
      const outputChunk = this.crypt(type, cipherAlgorithm, cipherChaining, key, iv, inputChunk)

      outputChunks.push(outputChunk)

      i++
    }

    // 모든 출력 청크를 연결합니다.
    let output = Buffer.concat(outputChunks)

    if (type === 'encrypt') {
      output = Buffer.concat([this.cryptoTool.createUInt32LEBuffer(input.length, this.iOffset), output])
    } else {
      const length = input.readUInt32LE(0)
      output = output.subarray(0, length)
    }

    return output
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
  private convertPasswordToKey(password: string, hashAlgorithm: string, salt: Buffer, spinCount: number, keyBits: number, blockKey: Buffer): Buffer {
    // 비밀번호를 유니코드 버퍼로 변환
    const passwordBuffer = Buffer.from(password, 'utf16le')

    // 초기 해시를 생성
    let key = this.cryptoTool.hash(hashAlgorithm, salt, passwordBuffer)

    // spinCount 횟수만큼 재생성
    for (let i = 0; i < spinCount; i++) {
      const iterator = this.cryptoTool.createUInt32LEBuffer(i)
      key = this.cryptoTool.hash(hashAlgorithm, iterator, key)
    }

    // 최종 해시를 생성
    key = this.cryptoTool.hash(hashAlgorithm, key, blockKey)

    // keyBits 길이에 맞게 키를 자르거나 패딩
    const keyBytes = keyBits / 8
    if (key.length < keyBytes) {
      const tmp = Buffer.alloc(keyBytes, 0x36)
      key.copy(tmp)
      key = tmp
    } else if (key.length > keyBytes) {
      key = key.subarray(0, keyBytes)
    }

    return key
  }


  private createEncryptedPackage(data: Buffer): Buffer {
    return this.cryptPackage(
      'encrypt',
      this.objEncInfo.package.cipherAlgorithm,
      this.objEncInfo.package.cipherChaining,
      this.objEncInfo.package.hashAlgorithm,
      this.objEncInfo.package.blockSize,
      this.objEncInfo.package.salt,
      this.packageKey,
      data
    )
  }


  private createEncryptedHmacKey(hmacKey: Buffer): Buffer {
    const hmacKeyIV = this.cryptoTool.createIV(
      this.objEncInfo.package.hashAlgorithm,
      this.objEncInfo.package.salt,
      this.objEncInfo.package.blockSize,
      BLOCK_KEY.INTEGRITY.HMAC_KEY,
    )

    return this.crypt(
      'encrypt',
      this.objEncInfo.package.cipherAlgorithm,
      this.objEncInfo.package.cipherChaining,
      this.packageKey,
      hmacKeyIV,
      hmacKey
    )
  }


  private createEncryptedHmacValue(hmacKey: Buffer, encryptedPackage: Buffer): Buffer {
    const hmacValue = this.cryptoTool.hmac(this.objEncInfo.package.hashAlgorithm, hmacKey, encryptedPackage)

    const hmacValueIV = this.cryptoTool.createIV(
      this.objEncInfo.package.hashAlgorithm,
      this.objEncInfo.package.salt,
      this.objEncInfo.package.blockSize,
      BLOCK_KEY.INTEGRITY.HMAC_VALUE,
    )

    return this.crypt(
      'encrypt',
      this.objEncInfo.package.cipherAlgorithm,
      this.objEncInfo.package.cipherChaining,
      this.packageKey,
      hmacValueIV,
      hmacValue
    )
  }


  private createEncryptedKeyValue(password: string): Buffer {
    const key = this.convertPasswordToKey(
      password,
      this.objEncInfo.key.hashAlgorithm,
      this.objEncInfo.key.salt,
      this.objEncInfo.key.spinCount,
      this.objEncInfo.key.keyBits,
      BLOCK_KEY.KEY
    )

    return this.crypt(
      'encrypt',
      this.objEncInfo.key.cipherAlgorithm,
      this.objEncInfo.key.cipherChaining,
      key,
      this.objEncInfo.key.salt,
      this.packageKey
    )
  }


  private createEncryptedVerifierHashInput(password: string, verifierHashInput: Buffer): Buffer {
    const verifierHashInputKey = this.convertPasswordToKey(
      password,
      this.objEncInfo.key.hashAlgorithm,
      this.objEncInfo.key.salt,
      this.objEncInfo.key.spinCount,
      this.objEncInfo.key.keyBits,
      BLOCK_KEY.VERIFIER_HASH.INPUT
    )

    return this.crypt(
      'encrypt',
      this.objEncInfo.key.cipherAlgorithm,
      this.objEncInfo.key.cipherChaining,
      verifierHashInputKey,
      this.objEncInfo.key.salt,
      verifierHashInput
    )
  }


  private createEncryptedVerifierHashValue(password: string, verifierHashInput: Buffer): Buffer {
    const verifierHashValueKey = this.convertPasswordToKey(
      password,
      this.objEncInfo.key.hashAlgorithm,
      this.objEncInfo.key.salt,
      this.objEncInfo.key.spinCount,
      this.objEncInfo.key.keyBits,
      BLOCK_KEY.VERIFIER_HASH.VALUE
    )

    return this.crypt(
      'encrypt',
      this.objEncInfo.key.cipherAlgorithm,
      this.objEncInfo.key.cipherChaining,
      verifierHashValueKey,
      this.objEncInfo.key.salt,
      this.cryptoTool.hash(this.objEncInfo.key.hashAlgorithm, verifierHashInput)
    )
  }
}