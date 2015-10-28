/**
 * Implementation of type KdfParams<br/>
 * <br/>
 * @requires util
 * @module type/Kdf
 */

module.exports = KdfParams;

var util = require('../util.js');

/**
 * @constructor
 */
function KdfParams() {
  this.hash = 0;
  this.cipher = 0;
}

/**
 * Parsing method for KdfParams
 * @param {String} input Input to read the KdfParams from
 */
KdfParams.prototype.read = function (bytes) {
  var len = bytes.charCodeAt(0);
  var reserved = bytes.charCodeAt(1);
  this.hash = bytes.charCodeAt(2);
  this.cipher = bytes.charCodeAt(3);
  return 4;
};

KdfParams.prototype.write = function () {
  var res = [];
  res[0] = 3;
  res[1] = 1;
  res[2] = this.hash;
  res[3] = this.cipher;
  return util.bin2str(res);
};
