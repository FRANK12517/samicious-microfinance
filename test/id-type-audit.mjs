import fs from 'node:fs';

const source = fs.readFileSync(new URL('../index.html', import.meta.url), 'utf8');
const required = [
  'const CUSTOMER_ID_TYPES=["Ghana Card","Voters ID","NHIS","Passport","No ID"]',
  'Select Your ID Type',
  'Select ID Type',
  'Enter Your Selected ID Number',
  'CUSTOMER_ID_TYPES_REQUIRING_NUMBER',
  'idType',
  'idNumber:idType==="No ID"?"":idNumber',
  'el.querySelector("#expCust").onclick=()=>exportCSV("customers.csv",customers,["customerNo","fullName","phone","idType","idNumber"'
];
for (const marker of required) {
  if (!source.includes(marker)) throw new Error(`Missing marker: ${marker}`);
}
if (source.includes('<label>National ID / Passport No.</label><input id="f_idnum"')) {
  throw new Error('Legacy customer registration field is still active');
}
console.log('Customer ID type audit passed.');
console.log('Supported types: Ghana Card, Voters ID, NHIS, Passport, No ID.');
console.log('Conditional number validation and No ID clearing are present.');
