// Implementation of ECDSA

/**
 * @requires crypto/hash
 * @requires crypto/public_key/jsbn
 * @requires util
 * @module crypto/public_key/ecdsa
 */

var hash = require('../hash'),
  curves = require('./curves.js'),
  BigInteger = require('./jsbn.js'),
  util = require('../../util.js');

function ECDSA() {
  
  function sign(curve, hash_algo, m, w) {
    curve = curves.get(curve.oid);
    w = curve.keyFromPrivate(w.toByteArray());
    var h = util.str2bin(hash.digest(hash_algo, m));
    var signature = w.sign(h);
    var result = [];
    result[0] = new BigInteger(signature.r.toArray()).toMPI();
    result[1] = new BigInteger(signature.s.toArray()).toMPI();
    return result;
  }

  function verify(curve, hash_algo, r, s, m, gw) {
    curve = curves.get(curve.oid);
    gw = curve.keyFromPublic(gw.toByteArray());
    var h = util.str2bin(hash.digest(hash_algo, m));
    return gw.verify(h, {r: r.toByteArray(), s: s.toByteArray()});
  }

  function generate(curve, bits, material) {
    return curves.generate(curve, bits, material);
  }
  
  this.sign = sign;
  this.verify = verify;
  this.generate = generate;
}

module.exports = ECDSA;
