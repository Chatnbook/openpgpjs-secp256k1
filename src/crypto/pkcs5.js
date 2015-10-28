/**
 * PKCS5 padding
 * @module crypto/pkcs5
 */

function getPkcs5Padding(length) {
  var c = 8 - (length % 8);
  var res = "";
  for (var i = 0; i < c; ++i)
    res += String.fromCharCode(c);
  return res;
}

function addPadding(msg) {
  return msg + getPkcs5Padding(msg.length);
}

function removePadding(msg) {
  var len = msg.length;
  var c = msg.charCodeAt(len - 1);
  if (c >= 1 && c <= 8)
    return msg.substr(0, len - c);
  return msg;
}

module.exports = {
  addPadding: addPadding,
  removePadding: removePadding
};
