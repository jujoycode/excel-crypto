# excel-crypto

> xlsx encrypt/decrypt based on ECMA376

## Installation

```bash
# npm
npm install excel-crypto

# yarn
yarn add excel-crypto

# pnpm
pnpm install excel-crypto
```

## Usage

```javascript
# example

import { XLSX_Cryptor } from "excel-crypto";
import { readFileSync, writeFileSync } from "fs";

const XlsxCryptor = new XLSX_Cryptor();

// 1. get Buffer
const fileBuffer = readFileSync('./file_path');

// 2. get encrypt Buffer
const encryptFile = XlsxCryptor.encrypt({
  data: fileBuffer,
  password: 'your_password',
});

// 3. create new file (.xlsx)
writeFileSync('./new_path', encryptFile)
```

## Authors

- \_jujoycode - Project initial and development

## Version History

- 1.0.1

  - 🔨 build with esBuild (`Bundling`, `Minify`, `Tree Shaking`)

- 1.0.0
  - ✨ Encrypt XLSX

## License

Write your license info here (ex. This project is licensed under the [MIT] License)
