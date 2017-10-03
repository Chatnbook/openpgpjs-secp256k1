/**
 * Implementation of type EcdhParams<br/>
 * <br/>
 * @requires util
 * @module type/EcdhParams
 */

module.exports = EcdhParams;

var util = require('../util.js');

/**
 * @constructor
 */
function EcdhParams(data) {
  this.data = data || '';
}

/**
 * Parsing method for EcdhParams
 * @param {String} bytes Input to read the EcdhParams from
 */
EcdhParams.prototype.read = function (bytes) {
  var len = bytes.charCodeAt(0);
  this.data = bytes.substr(1, len);
  return 1 + len;
};

EcdhParams.prototype.write = function () {
  return String.fromCharCode(this.data.length)
    + this.data;
};
