import { readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { XLSX_Cryptor } from "./src";

const ppt = readFileSync(join(__dirname, 'target', 'test1.ppt'))
const doc = readFileSync(join(__dirname, 'target', 'test1.doc'))
const xls = readFileSync(join(__dirname, 'target', 'test1.xls'))
const pptx = readFileSync(join(__dirname, 'target', 'test2.pptx'))
const docx = readFileSync(join(__dirname, 'target', 'test2.docx'))
const xlsx = readFileSync(join(__dirname, 'target', 'test2.xlsx'))

const password = "12345"

const enc_ppt = new XLSX_Cryptor().encrypt({
  data: ppt,
  password
})

const enc_doc = new XLSX_Cryptor().encrypt({
  data: doc,
  password
})

const enc_xls = new XLSX_Cryptor().encrypt({
  data: xls,
  password
})

const enc_pptx = new XLSX_Cryptor().encrypt({
  data: pptx,
  password
})

const enc_docx = new XLSX_Cryptor().encrypt({
  data: docx,
  password
})

const enc_xlsx = new XLSX_Cryptor().encrypt({
  data: xlsx,
  password
})

writeFileSync(join(__dirname, 'result', 'enc1.ppt'), enc_ppt)
writeFileSync(join(__dirname, 'result', 'enc1.doc'), enc_doc)
writeFileSync(join(__dirname, 'result', 'enc1.xls'), enc_xls)
writeFileSync(join(__dirname, 'result', 'enc2.pptx'), enc_pptx)
writeFileSync(join(__dirname, 'result', 'enc2.docx'), enc_docx)
writeFileSync(join(__dirname, 'result', 'enc2.xlsx'), enc_xlsx)