/**
 * Implementation of type Oid<br/>
 * <br/>
 * An object identifier in the sense of {@link https://tools.ietf.org/html/rfc6637#section-11|RFC6637, section 11}.
 * @requires util
 * @module type/oid
 */

module.exports = Oid;

var util = require('../util.js');

/**
 * @constructor
 */
function Oid(oid) {
  this.oid = oid || '';
}

/**
 * Parsing method for an Oid
 * @param {String} input Input to read the Oid from
 */
Oid.prototype.read = function (bytes) {
  var len = bytes.charCodeAt(0);
  this.oid = bytes.substr(1, len);
  return 1 + this.oid.length;
};

Oid.prototype.write = function () {
  var bytes = String.fromCharCode(this.oid.length);
  bytes += this.oid;
  return bytes;
};
