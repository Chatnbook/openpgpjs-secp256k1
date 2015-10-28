/**
 * @requires util
 * @module crypto/public_key/curves
 */

var EC = require('elliptic').ec,
  util = require('../../util.js');

var curves = {
  nistp256: util.bin2str([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]),
  nistp384: util.bin2str([0x2B, 0x81, 0x04, 0x00, 0x22]),
  nistp521: util.bin2str([0x2B, 0x81, 0x04, 0x00, 0x23]),
  secp256k1: util.bin2str([0x2B, 0x81, 0x04, 0x00, 0x0A]),
};

module.exports = {
  get: function (oid) {
    for (var name in curves) {
      if (curves[name] === oid)
        return new EC(name);
    }
    return new EC(name);
  }
};
