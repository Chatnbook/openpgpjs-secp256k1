// Implementation of ECDH

/**
 * @requires crypto/hash
 * @requires crypto/cipher
 * @requires crypto/rfc3394
 * @requires crypto/public_key/curves
 * @requires crypto/public_key/jsbn
 * @requires enums
 * @requires util
 * @module crypto/public_key/ecdh
 */

var AES = require('aes'), 
  BigInteger = require('./jsbn.js'),
  curves = require('./curves.js'),
  cipher = require('../cipher'),
  hash = require('../hash'),
  rfc3394 = require('../rfc3394.js'),
  enums = require('../../enums.js'),
  util = require('../../util.js');

function buildHashParam(publicKeyAlgo, curveOid, kdfParams, fingerprint) {
  var m = [];
  m.push(curveOid.write());
  m.push(String.fromCharCode(enums.write(enums.publicKey, publicKeyAlgo)));
  m.push(kdfParams.write());
  m.push("Anonymous Sender    ");
  m.push(fingerprint);
  return m.join('');
}

/// RFC 6637 7. Key Derivation Function
function kdf(hashAlgo, cipherAlgo, x, param) {
  var len = cipher[cipherAlgo].keySize;
  var m = [];
  m.push(util.bin2str([0, 0, 0, 1]));
  m.push(util.bin2str(x));
  m.push(param);
  m = m.join('');
  return hash.digest(hashAlgo, m).slice(0, len);
}

function ECDH() {
  
  function encrypt(publicKeyAlgo, curve, kdfParams, m, R, fingerprint) {
    var param = buildHashParam(publicKeyAlgo, curve, kdfParams, fingerprint);
    curve = curves.get(curve.oid);
    var cipherAlgo = enums.read(enums.symmetric, kdfParams.cipher);
    var v = curve.genKeyPair();
    R = curve.keyFromPublic(R.toByteArray());
    var x = v.derive(R.getPublic());
    var Z = kdf(kdfParams.hash, cipherAlgo, x.toArray(), param);
    var C = rfc3394.wrap(cipherAlgo, Z, m);
    return {
      V: new BigInteger(v.getPublic().encode()), 
      C: util.bin2str(C)
    };
  }
  
  function decrypt(publicKeyAlgo, curve, kdfParams, V, C, r, fingerprint) {
    var param = buildHashParam(publicKeyAlgo, curve, kdfParams, fingerprint);
    curve = curves.get(curve.oid);
    var cipherAlgo = enums.read(enums.symmetric, kdfParams.cipher);
    V = curve.keyFromPublic(V.toByteArray());
    r = curve.keyFromPrivate(r.toByteArray());
    var x = r.derive(V.getPublic());
    var Z = kdf(kdfParams.hash, cipherAlgo, x.toArray(), param);
    var m = rfc3394.unwrap(cipherAlgo, Z, C);
    return new BigInteger(m);
  }

  this.decrypt = decrypt;
  this.encrypt = encrypt;
}

module.exports = ECDH;
