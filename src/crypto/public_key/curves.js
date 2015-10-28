/**
 * @requires util
 * @requires enum
 * @module crypto/public_key/curves
 */

var EC = require('elliptic').ec,
  BigInteger = require('./jsbn.js'),
  util = require('../../util.js'),
  enums = require('../../enums.js');

var curves = {
  nistp256: {
    oid: util.bin2str([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]),
    bits: 256,
    hash: enums.hash.sha256,
    cipher: enums.symmetric.aes128,
  },
  nistp384: {
    oid: util.bin2str([0x2B, 0x81, 0x04, 0x00, 0x22]),
    bits: 384,
    hash: enums.hash.sha384,
    cipher: enums.symmetric.aes192,
  },
  nistp521: {
    oid: util.bin2str([0x2B, 0x81, 0x04, 0x00, 0x23]),
    bits: 521,
    hash: enums.hash.sha512,
    cipher: enums.symmetric.aes256,
  },
  secp256k1: {
    oid: util.bin2str([0x2B, 0x81, 0x04, 0x00, 0x0A]),
    bits: 256,
    hash: enums.hash.sha256,
    cipher: enums.symmetric.aes128,
  }
};

function getCurve(oid_or_name) {
  for (var name in curves) {
    if (curves[name].oid === oid_or_name || name == oid_or_name) {
      var curve = new EC(name);
      curve.oid = curves[name].oid;
      curve.hash_id = curves[name].hash;
      curve.cipher_id = curves[name].cipher;
      return curve;
    }
  }
  throw new Error('Not valid curve');
}

function generate(curve, bits) {
  return new Promise(function (resolve) {
    curve = getCurve(curve);
    var r = curve.genKeyPair();
    var key = {
      oid: curve.oid,
      R: new BigInteger(r.getPublic().encode()),
      r: new BigInteger(r.getPrivate().toArray()),
      hash: curve.hash_id,
      cipher: curve.cipher_id
    };
    resolve(key);
  });
}

module.exports = {
  get: getCurve,
  generate: generate
};
