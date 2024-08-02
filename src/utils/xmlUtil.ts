import { XMLBuilder } from "fast-xml-parser";

export class XmlUtil {
  public createEncXml(objPackageData: any, objKeyData: any, objIntegrion: any) {
    const options = {
      ignoreAttributes: false,
      format: true,
      suppressEmptyNode: true
    };

    const xmlContent = new XMLBuilder(options).build({
      'encryption': {
        '@_xmlns': 'http://schemas.microsoft.com/office/2006/encryption',
        '@_xmlns:p': 'http://schemas.microsoft.com/office/2006/keyEncryptor/password',
        '@_xmlns:c': 'http://schemas.microsoft.com/office/2006/keyEncryptor/certificate',
        'keyData': {
          '@_saltSize': objPackageData.salt.length,
          '@_blockSize': objPackageData.blockSize,
          '@_keyBits': objPackageData.keyBits,
          '@_hashSize': objPackageData.hashSize,
          '@_cipherAlgorithm': objPackageData.cipherAlgorithm,
          '@_cipherChaining': objPackageData.cipherChaining,
          '@_hashAlgorithm': objPackageData.hashAlgorithm,
          '@_saltValue': objPackageData.salt.toString('base64'),
        },
        'dataIntegrity': {
          '@_encryptedHmacKey': objIntegrion.encryptedHmacKey.toString('base64'),
          '@_encryptedHmacValue': objIntegrion.encryptedHmacValue.toString('base64'),
        },
        'keyEncryptors': {
          'keyEncryptor': {
            '@_uri': 'http://schemas.microsoft.com/office/2006/keyEncryptor/password',
            'p:encryptedKey': {
              '@_spinCount': objKeyData.spinCount,
              '@_saltSize': objKeyData.salt.length,
              '@_blockSize': objKeyData.blockSize,
              '@_keyBits': objKeyData.keyBits,
              '@_hashSize': objKeyData.hashSize,
              '@_cipherAlgorithm': objKeyData.cipherAlgorithm,
              '@_cipherChaining': objKeyData.cipherChaining,
              '@_hashAlgorithm': objKeyData.hashAlgorithm,
              '@_saltValue': objKeyData.salt.toString('base64'),
              '@_encryptedVerifierHashInput': objKeyData.encryptedVerifierHashInput.toString('base64'),
              '@_encryptedVerifierHashValue': objKeyData.encryptedVerifierHashValue.toString('base64'),
              '@_encryptedKeyValue': objKeyData.encryptedKeyValue.toString('base64'),
            }
          }
        }
      }
    })
    return xmlContent
  }
}