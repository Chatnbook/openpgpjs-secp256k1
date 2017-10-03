// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2015 Kryptokit
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

/**
 * Implementation of type KDF parameters RFC 6637<br/>
 * <br/>
 * @requires util
 * @requires enums
 * @module type/kdf_params
 */

'use strict';

import util from '../util.js';
import enums from '../enums.js';

module.exports = KdfParams;

/**
 * @constructor
 * @param  {enums.hash}       hash    Hash algorithm
 * @param  {enums.symmetric}  cipher  Symmetric algorithm
 */
function KdfParams(hash, cipher) {
  this.hash = hash || enums.hash.sha1;
  this.cipher = cipher || enums.symmetric.aes128;
}

/**



* Parsing method for KdfParams
* @param {String} input Input to read the KdfParams from
*/
/*KdfParams.prototype.read = function (bytes) {
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
 return util.bin2str(res);*/

 * Read KdfParams from an Uint8Array
 * @param  {Uint8Array}  input  Where to read the KdfParams from
 * @return {Number}             Number of read bytes
 */
KdfParams.prototype.read = function (input) {
  if (input.length < 4 || input[0] !== 3 || input[1] !== 1) {
    throw new Error('Cannot read KdfParams');
  }
  this.hash = input[2];
  this.cipher = input[3];
  return 4;
};

/**
 * Write KdfParams to an Uint8Array
 * @return  {Uint8Array}  Array with the KdfParams value
 */
KdfParams.prototype.write = function () {
  return new Uint8Array([3, 1, this.hash, this.cipher]);
};
