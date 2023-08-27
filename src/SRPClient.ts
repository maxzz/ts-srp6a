import { BigInteger } from './biginteger';
// import * as sjcl from 'ts-sjcl';
// import { sjcl } from 'ts-sjcl';
import sjcl from 'ts-sjcl';
import * as sha1 from './sha1';

/*
 * Implementation of an SRP client conforming
 * to the SRP protocol 6A (see RFC5054).
 */

export class SRPClient {
    private username: string;
    private password: string;

    // Initialize hash function
    private hashFn: string;

    private N: BigInteger;
    private g: BigInteger;
    //private gBn: BigInteger;

    // Pre-compute k from N and g.
    private k: BigInteger;

    // Convenience big integer objects for 1 and 2.
    private one: BigInteger;
    private two: BigInteger;

    /*
     * Construct an SRP object with a username,
     * password, and the bits identifying the 
     * group (1024 [default], 1536 or 2048 bits).
     */
    constructor(username: string, password: string, group?: number, hashFn?: string) {

        // Verify presence of username.
        if (!username) {
            throw 'Username cannot be empty.';
        }

        // Store username/password.
        this.username = username;
        this.password = password;

        // Initialize hash function
        this.hashFn = hashFn || 'sha-1';

        // Retrieve initialization values.
        var initVal = this.initVals[group || 1024];

        // Set N and g from initialization values.
        this.N = new BigInteger(initVal.N, 16);
        this.g = new BigInteger(initVal.g, 16);
        //this.gBn = new BigInteger(initVal.g, 16);

        // Pre-compute k from N and g.
        this.k = this.kPrecompute();

        // Convenience big integer objects for 1 and 2.
        this.one = new BigInteger("1", 16);
        this.two = new BigInteger("2", 16);
    }

    toHexString(bi: number | BigInteger): string {
        let hex = bi.toString(16);
        if (hex.length % 2 === 1) {
            hex = "0" + hex;
        }
        return hex;
    }
    padLeft(orig: string, len: number): string {
        if (orig.length > len) {
            return orig;
        }
        const arr = Array(len - orig.length + 1);
        return arr.join("0") + orig;
    }
    bytesToHex(bytes: number[]) {
        const self = this;
        const b = bytes.map(function (x) { return self.padLeft(self.toHexString(x), 2); });
        return b.join("");
    }
    hexToBytes(hex: string): number[] {
        if (hex.length % 2 === 1) {
            throw new Error("hexToBytes can't have a string with an odd number of characters.");
        }
        if (hex.indexOf("0x") === 0) {
            hex = hex.slice(2);
        }
        return hex.match(/../g)?.map(function (x) { return parseInt(x, 16); }) || [];
    }
    stringToBytes(str: string): number[] {
        let bytes = [];
        for (var i = 0; i < str.length; ++i) {
            bytes.push(str.charCodeAt(i));
        }
        return bytes;
    }
    bytesToString(byteArr: number[]): string {
        let str = '';
        for (var i = 0; i < byteArr.length; i++) {
            str += String.fromCharCode(byteArr[i]);
        }
        return str;
    }

    /*
     * Calculate k = H(N || g), which is used
     * throughout various SRP calculations.
     */
    kPrecompute(): BigInteger {
        // Convert to hex values.
        const toHash = [
            this.toHexString(this.N),
            this.toHexString(this.g)
        ] as const;

        // Return hash as a BigInteger.
        return this.paddedHash(toHash);
    }

    /*
     * Calculate x = SHA1(s | SHA1(I | ":" | P))
     */
    calculateX(saltHex: string): BigInteger {
        // Verify presence of parameters.
        if (!saltHex) {
            throw new Error('Missing parameter.');
        }

        if (!this.username || !this.password) {
            throw new Error('Username and password cannot be empty.');
        }

        const usernameBytes = this.stringToBytes(this.username);
        const passwordBytes = this.hexToBytes(this.password);

        const upBytes = usernameBytes.concat([58]).concat(passwordBytes);
        const upHash = this.hash(this.bytesToString(upBytes));
        const upHashBytes = this.hexToBytes(upHash);

        const saltBytes = this.hexToBytes(saltHex);
        const saltUpBytes = saltBytes.concat(upHashBytes);
        const saltUpHash = this.hash(this.bytesToString(saltUpBytes));

        const xtmp = new BigInteger(saltUpHash, 16);
        if (xtmp.compareTo(this.N) < 0) {
            return xtmp;
        } else {
            const one = new BigInteger(1, 16);
            return xtmp.mod(this.N.subtract(one));
        }
    }

    /*
     * Calculate v = g^x % N
     */
    calculateV(salt: string) {
        // Verify presence of parameters.
        if (!salt) {
            throw 'Missing parameter.';
        }

        // Get X from the salt value.
        const x = this.calculateX(salt);

        // Calculate and return the verifier.
        return this.g.modPow(x, this.N);
    }

    /*
     * Calculate u = SHA1(PAD(A) | PAD(B)), which serves
     * to prevent an attacker who learns a user's verifier
     * from being able to authenticate as that user.
     */
    calculateU(A: BigInteger, B: BigInteger): BigInteger {
        // Verify presence of parameters.
        if (!A || !B) {
            throw 'Missing parameter(s).';
        }

        // Verify value of A and B.
        if (A.mod(this.N).toString() == '0' || B.mod(this.N).toString() == '0') {
            throw 'ABORT: illegal_parameter';
        }

        // Convert A and B to hexadecimal.
        const toHash = [this.toHexString(A), this.toHexString(B)] as const;

        // Return hash as a BigInteger.
        return this.paddedHash(toHash);
    }

    canCalculateA(a: BigInteger): boolean {
        if (!a) {
            throw 'Missing parameter.';
        }
        return Math.ceil(a.bitLength() / 8) >= 256 / 8;
    }

    /*
     * 2.5.4 Calculate the client's public value A = g^a % N,
     * where a is a random number at least 256 bits in length.
     */
    calculateA(a: BigInteger): BigInteger {
        // Verify presence of parameter.
        if (!a) {
            throw 'Missing parameter.';
        }

        if (!this.canCalculateA(a)) {
            throw 'Client key length is less than 256 bits.';
        }

        // Return A as a BigInteger.
        const A = this.g.modPow(a, this.N);

        if (A.mod(this.N).toString() == '0') {
            throw 'ABORT: illegal_parameter';
        }

        return A;
    }

    /*
     * Calculate match M = H(H(N) XOR H(g) | H(username) | s | A | B | K)
     */
    calculateM1(A: BigInteger, B: BigInteger, K: string, salt: string) {
        // Verify presence of parameters.
        if (!A || !B || !K || !salt) {
            throw 'Missing parameter(s).';
        }

        // Verify value of A and B.
        if (A.mod(this.N).toString() == '0' ||
            B.mod(this.N).toString() == '0') {
            throw 'ABORT: illegal_parameter';
        }

        const hashN = this.hexHash(this.toHexString(this.N));
        const hashg = this.hexHash(this.toHexString(this.g));

        const hashUsername = this.hash(this.username);

        var xorNg_bytes = [],
            hashN_bytes = this.hexToBytes(hashN),
            hashg_bytes = this.hexToBytes(hashg);

        for (var i = 0; i < hashN_bytes.length; i++) {
            xorNg_bytes[i] = hashN_bytes[i] ^ hashg_bytes[i];
        }

        var xorNg = this.bytesToHex(xorNg_bytes);

        var aHex = this.toHexString(A);
        var bHex = this.toHexString(B);

        var toHash = [xorNg, hashUsername, salt, aHex, bHex, K];
        var toHash_str = '';

        for (var j = 0; j < toHash.length; j++) {
            toHash_str += toHash[j];
        }

        return new BigInteger(this.hexHash(toHash_str), 16);
    }

    /*
     * Calculate match M = H(H(N) XOR H(g) | H(username) | s | A | B | K) and return as hex string
     */
    calculateM(A: BigInteger, B: BigInteger, K: string, salt: string) {
        // Verify presence of parameters.
        if (!A || !B || !K || !salt) {
            throw 'Missing parameter(s).';
        }

        // Verify value of A and B.
        if (A.mod(this.N).toString() == '0' || B.mod(this.N).toString() == '0') {
            throw 'ABORT: illegal_parameter';
        }

        const hashN = this.hexHash(this.toHexString(this.N));
        const hashg = this.hexHash(this.toHexString(this.g));

        const hashUsername = this.hash(this.username);

        var xorNg_bytes = [],
            hashN_bytes = this.hexToBytes(hashN),
            hashg_bytes = this.hexToBytes(hashg);

        for (var i = 0; i < hashN_bytes.length; i++) {
            xorNg_bytes[i] = hashN_bytes[i] ^ hashg_bytes[i];
        }

        var xorNg = this.bytesToHex(xorNg_bytes);

        var aHex = this.toHexString(A);
        var bHex = this.toHexString(B);

        var toHash = [xorNg, hashUsername, salt, aHex, bHex, K];
        var toHash_str = '';

        for (var j = 0; j < toHash.length; j++) {
            toHash_str += toHash[j];
        }

        return this.hexHash(toHash_str);
    }

    /*
     * Calculate match M = H(A, B, K) or M = H(A, M, K)
     */
    calculateM2(A: BigInteger, B_or_M: BigInteger, K: string) {

        // Verify presence of parameters.
        if (!A || !B_or_M || !K) {
            throw 'Missing parameter(s).';
        }

        // Verify value of A and B.
        if (A.mod(this.N).toString() == '0' || B_or_M.mod(this.N).toString() == '0') {
            throw 'ABORT: illegal_parameter';
        }

        const aHex = this.toHexString(A);
        const bHex = this.toHexString(B_or_M);

        const toHash = [aHex, bHex, K];
        let toHash_str = '';

        for (var j = 0; j < toHash.length; j++) {
            toHash_str += toHash[j];
        }

        return new BigInteger(this.hexHash(toHash_str), 16);
    }

    /*
     * Calculate the client's premaster secret 
     * S = (B - (k * g^x)) ^ (a + (u * x)) % N
     */
    calculateS(B: BigInteger, salt: string, uu: BigInteger, aa: BigInteger) {

        // Verify presence of parameters.
        if (!B || !salt || !uu || !aa) {
            throw 'Missing parameters.';
        }

        // Verify value of B.
        if (B.mod(this.N).toString() == '0') {
            throw 'ABORT: illegal_parameter';
        }

        // Calculate X from the salt.
        const x = this.calculateX(salt);

        // Calculate bx = g^x % N
        const bx = this.g.modPow(x, this.N);

        // Calculate ((B + N * k) - k * bx) % N
        const btmp = B.add(this.N.multiply(this.k)).subtract(bx.multiply(this.k)).mod(this.N);

        // Finish calculation of the premaster secret.
        return btmp.modPow(x.multiply(uu).add(aa), this.N);
    }

    calculateK(S: BigInteger) {
        return this.hexHash(this.toHexString(S));
    }

    /*
     * Helper functions for random number
     * generation and format conversion.
     */

    /* Generate a random big integer */
    srpRandom(): BigInteger {

        const words = sjcl.random.randomWords(8, 0);
        const hex = sjcl.codec.hex.fromBits(words);

        // Verify random number large enough.
        if (hex.length != 64) {
            throw 'Invalid random number size.';
        }

        let rv = new BigInteger(hex, 16);

        if (rv.compareTo(this.N) >= 0) {
            rv = rv.mod(this.N.subtract(this.one)); // tm: rv = a.mod(this.N.subtract(this.one)); where a is undefined
        }

        if (rv.compareTo(this.two) < 0) {
            rv = this.two;
        }

        return rv;
    }

    /* Return a random hexadecimal salt */
    randomHexSalt() {
        const words = sjcl.random.randomWords(8, 0);
        const hex = sjcl.codec.hex.fromBits(words);
        return hex;
    }

    /*
     * Helper functions for hasing/padding.
     */

    /*
     * SHA1 hashing function with padding: input 
     * is prefixed with 0 to meet N hex width.
     */
    paddedHash(array: readonly [string, string]): BigInteger {
        const nlen = 2 * ((this.toHexString(this.N).length * 4 + 7) >> 3);
        let toHash = '';

        for (var i = 0; i < array.length; i++) {
            toHash += this.nZeros(nlen - array[i].length) + array[i];
        }

        const hash = new BigInteger(this.hexHash(toHash), 16);
        return hash.mod(this.N);
    }

    /* 
     * Generic hashing function.
     */
    hash(str: string): string {
        switch (this.hashFn.toLowerCase()) {
            case 'sha-256': {
                const s = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(str));
                return this.nZeros(64 - s.length) + s;
            }
            case 'sha-1':
            default: {
                return sha1.calcSHA1(str);
            }
        }
    }

    /*
     * Hexadecimal hashing function.
     */
    hexHash(str: string): string {
        switch (this.hashFn.toLowerCase()) {
            case 'sha-256': {
                const s = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(sjcl.codec.hex.toBits(str)));
                return this.nZeros(64 - s.length) + s;
            }
            case 'sha-1':
            default: {
                return this.hash(this.pack(str));
            }
        }
    }

    /*
     * Hex to string conversion.
     */
    pack(hex: string): string {
        // To prevent null byte termination bug
        if (hex.length % 2 != 0) {
            hex = '0' + hex;
        }

        let i = 0;
        let ascii = '';

        while (i < hex.length / 2) {
            ascii = ascii + String.fromCharCode(parseInt(hex.substr(i * 2, 2), 16));
            i++;
        }

        return ascii;
    }

    /* Return a string with N zeros. */
    nZeros(n: number): string {
        if (n < 1) {
            return '';
        }
        const t = this.nZeros(n >> 1);
        return ((n & 1) == 0) ? t + t : t + t + '0';
    }

    /*
     * SRP group parameters, composed of N (hexadecimal
     * prime value) and g (decimal group generator).
     * See http://tools.ietf.org/html/rfc5054#appendix-A
     */
    initVals: Record<number, { N: string; g: string; }> = {
        1024: {
            N: 'EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C' +
                '9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4' +
                '8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29' +
                '7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A' +
                'FD5138FE8376435B9FC61D2FC0EB06E3',
            g: '2'

        },
        1536: {
            N: '9DEF3CAFB939277AB1F12A8617A47BBBDBA51DF499AC4C80BEEEA961' +
                '4B19CC4D5F4F5F556E27CBDE51C6A94BE4607A291558903BA0D0F843' +
                '80B655BB9A22E8DCDF028A7CEC67F0D08134B1C8B97989149B609E0B' +
                'E3BAB63D47548381DBC5B1FC764E3F4B53DD9DA1158BFD3E2B9C8CF5' +
                '6EDF019539349627DB2FD53D24B7C48665772E437D6C7F8CE442734A' +
                'F7CCB7AE837C264AE3A9BEB87F8A2FE9B8B5292E5A021FFF5E91479E' +
                '8CE7A28C2442C6F315180F93499A234DCF76E3FED135F9BB',
            g: '2'
        },
        2048: {
            N: 'AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC319294' +
                '3DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310D' +
                'CD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FB' +
                'D5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF74' +
                '7359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A' +
                '436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D' +
                '5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E73' +
                '03CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6' +
                '94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F' +
                '9E4AFF73',
            g: '2'
        },
        3072: {
            N: 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08' +
                '8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B' +
                '302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9' +
                'A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6' +
                '49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8' +
                'FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
                '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C' +
                '180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' +
                '3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D' +
                '04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D' +
                'B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226' +
                '1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
                'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC' +
                'E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF',
            g: '5'
        },
        4096: {
            N: 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08' +
                '8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B' +
                '302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9' +
                'A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6' +
                '49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8' +
                'FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
                '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C' +
                '180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' +
                '3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D' +
                '04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D' +
                'B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226' +
                '1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
                'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC' +
                'E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26' +
                '99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB' +
                '04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2' +
                '233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127' +
                'D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199' +
                'FFFFFFFFFFFFFFFF',
            g: '5'
        },
        6144: {
            N: 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08' +
                '8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B' +
                '302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9' +
                'A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6' +
                '49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8' +
                'FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
                '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C' +
                '180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' +
                '3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D' +
                '04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D' +
                'B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226' +
                '1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
                'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC' +
                'E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26' +
                '99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB' +
                '04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2' +
                '233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127' +
                'D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492' +
                '36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406' +
                'AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918' +
                'DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151' +
                '2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03' +
                'F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F' +
                'BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA' +
                'CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B' +
                'B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632' +
                '387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E' +
                '6DCC4024FFFFFFFFFFFFFFFF',
            g: '5'
        },
        8192: {
            N: 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08' +
                '8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B' +
                '302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9' +
                'A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6' +
                '49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8' +
                'FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
                '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C' +
                '180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' +
                '3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D' +
                '04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D' +
                'B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226' +
                '1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C' +
                'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC' +
                'E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26' +
                '99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB' +
                '04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2' +
                '233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127' +
                'D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492' +
                '36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406' +
                'AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918' +
                'DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151' +
                '2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03' +
                'F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F' +
                'BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA' +
                'CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B' +
                'B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632' +
                '387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E' +
                '6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA' +
                '3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C' +
                '5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9' +
                '22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC886' +
                '2F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A6' +
                '6D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC5' +
                '0846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268' +
                '359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6' +
                'FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E71' +
                '60C980DD98EDD3DFFFFFFFFFFFFFFFFF',
            g: '19'
        }
    };

    /*
     * Server-side SRP functions. These should not
     * be used on the client except for debugging.
     */

    /* Calculate the server's public value B. */
    calculateB(b: BigInteger, v: BigInteger): BigInteger {
        // Verify presence of parameters.
        if (!b || !v) {
            throw 'Missing parameters.';
        }

        const bb = this.g.modPow(b, this.N);
        const B = bb.add(v.multiply(this.k)).mod(this.N);
        return B;
    }

    /* Calculate the server's premaster secret */
    calculateServerS(A: BigInteger, v: BigInteger, u: BigInteger, B: BigInteger) {

        // Verify presence of parameters.
        if (!A || !v || !u || !B) {
            throw 'Missing parameters.';
        }

        // Verify value of A and B.
        if (A.mod(this.N).toString() == '0' || B.mod(this.N).toString() == '0') {
            throw 'ABORT: illegal_parameter';
        }

        return v.modPow(u, this.N).multiply(A).mod(this.N).modPow(B, this.N);
    }

} //class SRPClient
