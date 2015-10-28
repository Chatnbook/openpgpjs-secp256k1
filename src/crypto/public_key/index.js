/**
 * @requires crypto/public_key/dsa
 * @requires crypto/public_key/elgamal
 * @requires crypto/public_key/rsa
 * @requires crypto/public_key/ecdsa
 * @module crypto/public_key
 */
module.exports = {
  /** @see module:crypto/public_key/rsa */
  rsa: require('./rsa.js'),
  /** @see module:crypto/public_key/elgamal */
  elgamal: require('./elgamal.js'),
  /** @see module:crypto/public_key/dsa */
  dsa: require('./dsa.js'),
  /** @see module:crypto/public_key/ecdsa */
  ecdsa: require('./ecdsa.js')
};
