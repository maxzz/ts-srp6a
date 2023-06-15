# sjcl-ts

Stanford Javascript Crypto Library updated to ES6.

> Tiny 2.72kB AES-GCM library

- **Tiny**: about 2.72kB after gzipped
- **Mordern**: pure ESM package
- **Reliable**: based on [Stanford Javascript Crypto Library](https://github.com/bitwiseshiftleft/sjcl) with minimal customization

## Installation

```sh
pnpm add ts-sjcl
```

## Usage

```js
import sjcl from 'ts-sjcl'

const password = sjcl.codec.utf8String.toBits('PASSWORD')
const iv = sjcl.codec.utf8String.toBits('IV')

const cipher = new sjcl.cipher.aes(password)

export function encrypt(plaintext) {
  return sjcl.codec.base64.fromBits(
    sjcl.mode.gcm.encrypt(cipher, sjcl.codec.utf8String.toBits(plaintext), iv)
  )
}

export function decrypt(ciphertext) {
  return sjcl.codec.utf8String.fromBits(
    sjcl.mode.gcm.decrypt(cipher, sjcl.codec.base64.toBits(ciphertext), iv)
  )
}

console.log(encrypt('Hello World!'))
console.log(decrypt('0sFJ9r7c33z7gB4u1pD0xzuX48xaYVBGLj41UQ=='))
```

## Documentation

[https://bitwiseshiftleft.github.io/sjcl/doc](https://bitwiseshiftleft.github.io/sjcl/doc)

## Credits, refs, links

* [bitwiseshiftleft/sjcl](https://github.com/bitwiseshiftleft/sjcl) (6 years old, [@types](https://www.npmjs.com/package/@types/sjcl), [types](https://github.com/Evgenus/sjcl-typescript-definitions))
* [liufei/sjcl-es](https://github.com/liufei/sjcl-es) (ESM, no typescript definitions)

* [peterolson/BigInteger](https://github.com/peterolson/BigInteger.js)
* [alibaba-archive/node-biginteger](https://github.com/alibaba-archive/node-biginteger/blob/master/lib/BigInteger.js)
* [dasavrasov/SrpClientJS: biginteger.js](https://github.com/dasavrasov/SrpClientJS/blob/master/srp-client/src/srp/biginteger.js)
* [GH: 'BigInteger bnGetLowestSetBit'](https://github.com/search?q=BigInteger+bnGetLowestSetBit&type=code&ref=advsearch)
  * [travist/jsencrypt: jsbn.ts](https://github.com/travist/jsencrypt/blob/master/src/lib/jsbn/jsbn.ts)
  * [travist/jsencrypt: rng.ts](https://github.com/travist/jsencrypt/blob/master/src/lib/jsbn/rng.ts)
