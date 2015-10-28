// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

// The GPG4Browsers crypto interface

/**
 * @requires crypto/cipher
 * @requires crypto/public_key
 * @requires crypto/random
 * @requires type/mpi
 * @module crypto/crypto
 */

var random = require('./random.js'),
  cipher = require('./cipher'),
  publicKey = require('./public_key'),
  util = require('../util.js'),
  type_mpi = require('../type/mpi.js'),
  type_oid = require('../type/oid.js'),
  type_ecdh_params = require('../type/ecdh_params.js'),
  type_kdf_params = require('../type/kdf_params.js');

module.exports = {
  /**
   * Encrypts data using the specified public key multiprecision integers
   * and the specified algorithm.
   * @param {module:enums.publicKey} algo Algorithm to be used (See {@link http://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1})
   * @param {Array<module:type/mpi>} publicMPIs Algorithm dependent multiprecision integers
   * @param {module:type/mpi} data Data to be encrypted as MPI
   * @return {Array<module:type/mpi>} if RSA an module:type/mpi;
   * if elgamal encryption an array of two module:type/mpi is returned; otherwise null
   */
  publicKeyEncrypt: function(algo, publicMPIs, data, fingerprint) {
    var result = (function() {
      var m;
      switch (algo) {
        case 'rsa_encrypt':
        case 'rsa_encrypt_sign':
          var rsa = new publicKey.rsa();
          var n = publicMPIs[0].toBigInteger();
          var e = publicMPIs[1].toBigInteger();
          m = data.toBigInteger();
          return mapResult([rsa.encrypt(m, e, n)]);

        case 'elgamal':
          var elgamal = new publicKey.elgamal();
          var p = publicMPIs[0].toBigInteger();
          var g = publicMPIs[1].toBigInteger();
          var y = publicMPIs[2].toBigInteger();
          m = data.toBigInteger();
          return mapResult(elgamal.encrypt(m, g, p, y));

        case 'ecdh':
          var ecdh = new publicKey.ecdh();
          var curve = publicMPIs[0];
          var kdfParams = publicMPIs[2];
          var R = publicMPIs[1].toBigInteger();
          var res = ecdh.encrypt(algo, curve, kdfParams, data, R, util.hex2bin(fingerprint));
          return mapResult([res.V]).concat([new type_ecdh_params(res.C)]);

        default:
          return [];
      }
    })();
    
    return result;

    function mapResult(result) {
      return result.map(function (bn) {
        var mpi = new type_mpi();
        mpi.fromBigInteger(bn);
        return mpi;
      });
    }
  },

  /**
   * Decrypts data using the specified public key multiprecision integers of the private key,
   * the specified secretMPIs of the private key and the specified algorithm.
   * @param {module:enums.publicKey} algo Algorithm to be used (See {@link http://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1})
   * @param {Array<module:type/mpi>} publicMPIs Algorithm dependent multiprecision integers
   * of the public key part of the private key
   * @param {Array<module:type/mpi>} secretMPIs Algorithm dependent multiprecision integers
   * of the private key used
   * @param {module:type/mpi} data Data to be encrypted as MPI
   * @return {module:type/mpi} returns a big integer containing the decrypted data; otherwise null
   */

  publicKeyDecrypt: function(algo, keyIntegers, dataIntegers, fingerprint) {
    var p;

    var bn = (function() {
      switch (algo) {
        case 'rsa_encrypt_sign':
        case 'rsa_encrypt':
          var rsa = new publicKey.rsa();
          // 0 and 1 are the public key.
          var n = keyIntegers[0].toBigInteger();
          var e = keyIntegers[1].toBigInteger();
          // 2 to 5 are the private key.
          var d = keyIntegers[2].toBigInteger();
          p = keyIntegers[3].toBigInteger();
          var q = keyIntegers[4].toBigInteger();
          var u = keyIntegers[5].toBigInteger();
          var m = dataIntegers[0].toBigInteger();
          return rsa.decrypt(m, n, e, d, p, q, u);

        case 'elgamal':
          var elgamal = new publicKey.elgamal();
          var x = keyIntegers[3].toBigInteger();
          var c1 = dataIntegers[0].toBigInteger();
          var c2 = dataIntegers[1].toBigInteger();
          p = keyIntegers[0].toBigInteger();
          return elgamal.decrypt(c1, c2, p, x);

        case 'ecdh':
          var ecdh = new publicKey.ecdh();
          var curve = keyIntegers[0];
          var kdfParams = keyIntegers[2];
          var V = dataIntegers[0].toBigInteger();
          var C = dataIntegers[1].data;
          var r = keyIntegers[3].toBigInteger();
          return ecdh.decrypt(algo, curve, kdfParams, V, C, r, util.hex2bin(fingerprint));

        default:
          return null;
      }
    })();

    var result = new type_mpi();
    result.fromBigInteger(bn);
    return result;
  },

  /** Returns the number of integers comprising the private key of an algorithm
   * @param {String} algo The public key algorithm
   * @return {Integer} The number of integers.
   */
  getPrivateMpiCount: function(algo) {
    switch (algo) {
      case 'rsa_encrypt':
      case 'rsa_encrypt_sign':
      case 'rsa_sign':
        //   Algorithm-Specific Fields for RSA secret keys:
        //   - multiprecision integer (MPI) of RSA secret exponent d.
        //   - MPI of RSA secret prime value p.
        //   - MPI of RSA secret prime value q (p < q).
        //   - MPI of u, the multiplicative inverse of p, mod q.
        return 4;
      case 'elgamal':
        // Algorithm-Specific Fields for Elgamal secret keys:
        //   - MPI of Elgamal secret exponent x.
        return 1;
      case 'dsa':
        // Algorithm-Specific Fields for DSA secret keys:
        //   - MPI of DSA secret exponent x.
        return 1;
      case 'ecdh':
      case 'ecdsa':
        // Algorithm-Specific Fields for ECDSA or ECDH secret keys:
        //   - MPI of an integer representing the secret key.
        return 1;
      default:
        throw new Error('Unknown algorithm');
    }
  },

  getPublicMpiCount: function(algo) {
    // - A series of multiprecision integers comprising the key material:
    //   Algorithm-Specific Fields for RSA public keys:
    //       - a multiprecision integer (MPI) of RSA public modulus n;
    //       - an MPI of RSA public encryption exponent e.
    switch (algo) {
      case 'rsa_encrypt':
      case 'rsa_encrypt_sign':
      case 'rsa_sign':
        return 2;

        //   Algorithm-Specific Fields for Elgamal public keys:
        //     - MPI of Elgamal prime p;
        //     - MPI of Elgamal group generator g;
        //     - MPI of Elgamal public key value y (= g**x mod p where x  is secret).
      case 'elgamal':
        return 3;

        //   Algorithm-Specific Fields for DSA public keys:
        //       - MPI of DSA prime p;
        //       - MPI of DSA group order q (q is a prime divisor of p-1);
        //       - MPI of DSA group generator g;
        //       - MPI of DSA public-key value y (= g**x mod p where x  is secret).
      case 'dsa':
        return 4;

        //   Algorithm-Specific Fields for ECDSA public keys:
        //       - OID of curve;
        //       - MPI of EC point representing public key.
      case 'ecdsa':
        return 2;

        //   Algorithm-Specific Fields for ECDH public keys:
        //       - OID of curve;
        //       - MPI of EC point representing public key.
        //       - variable-length field containing KDF parameters.
      case 'ecdh':
        return 3;

      default:
        throw new Error('Unknown algorithm.');
    }
  },

  generateMpi: function(algo, bits, curve) {
    switch (algo) {
      case 'rsa_encrypt':
      case 'rsa_encrypt_sign':
      case 'rsa_sign':
        //remember "publicKey" refers to the crypto/public_key dir
        var rsa = new publicKey.rsa();
        return rsa.generate(bits, "10001").then(function(keyObject) {
          var output = [];
          output.push(keyObject.n);
          output.push(keyObject.ee);
          output.push(keyObject.d);
          output.push(keyObject.p);
          output.push(keyObject.q);
          output.push(keyObject.u);
          return mapResult(output);
        });

      case 'ecdsa':
        var ecdsa = new publicKey.ecdsa();
        return ecdsa.generate(curve, bits).then(function (key) {
          var output = [];
          output.push(new type_oid(key.oid));
          var mpi = new type_mpi();
          mpi.fromBigInteger(key.R);
          output.push(mpi);
          mpi = new type_mpi();
          mpi.fromBigInteger(key.r);
          output.push(mpi);
          return output;
        });

      case 'ecdh':
        var ecdh = new publicKey.ecdh();
        return ecdh.generate(curve, bits).then(function (key) {
          var output = [];
          output.push(new type_oid(key.oid));
          var mpi = new type_mpi();
          mpi.fromBigInteger(key.R);
          output.push(mpi);
          output.push(new type_kdf_params(key.hash, key.cipher));
          mpi = new type_mpi();
          mpi.fromBigInteger(key.r);
          output.push(mpi);
          return output;
        });

      default:
        throw new Error('Unsupported algorithm for key generation.');
    }

    function mapResult(result) {
      return result.map(function(bn) {
        var mpi = new type_mpi();
        mpi.fromBigInteger(bn);
        return mpi;
      });
    }
  },


  /**
   * generate random byte prefix as string for the specified algorithm
   * @param {module:enums.symmetric} algo Algorithm to use (see {@link http://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2})
   * @return {String} Random bytes with length equal to the block
   * size of the cipher
   */
  getPrefixRandom: function(algo) {
    return random.getRandomBytes(cipher[algo].blockSize);
  },

  /**
   * Generating a session key for the specified symmetric algorithm
   * @param {module:enums.symmetric} algo Algorithm to use (see {@link http://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2})
   * @return {String} Random bytes as a string to be used as a key
   */
  generateSessionKey: function(algo) {
    return random.getRandomBytes(cipher[algo].keySize);
  }
};
