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

```bash
# install package

npm i excel-crypto
```

```javascript
# example

import { XLSX_Cryptor } from "excel-crypto";
import { readFileSync } from "fs";

const XlsxCryptor = new XLSX_Cryptor();

// make Buffer
const fileBuffer = readFileSync("./your_path");

// get encrypt Buffer
const encryptFile = XlsxCryptor.encrypt({
  data: fileBuffer,
  password: "your_password",
});
```

## Authors

- \_jujoycode - Project initial and development

## Version History

- 1.0.0
  - ✨ Encrypt XLSX

## License

Write your license info here (ex. This project is licensed under the [MIT] License)
