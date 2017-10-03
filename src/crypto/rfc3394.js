// Implementation of RFC 3394 Key Wrap & Key Unwrap

var AES = require('aes');

function createArrayBuffer(data) {
  var len = data.length;
  var buff = new ArrayBuffer(len);
  var view = new Uint8Array(buff);
  for (var j = 0; j < len; ++j) {
    view[j] = data.charCodeAt(j);
  }
  return buff;
}

function unpack(data) {
  var len = data.length;
  var buff = createArrayBuffer(data);
  var view = new DataView(buff);
  var arr = new Array(len / 8);
  for (var i = 0; i < len / 8; ++i) {
    arr[i] = new Uint32Array(2);
    arr[i][0] = view.getUint32(i * 8);
    arr[i][1] = view.getUint32(i * 8 + 4);
  }
  return arr;
}

function pack(data) {
  var len = data.length;
  var buff = new ArrayBuffer(len * 8);
  var view = new DataView(buff);
  for (var i = 0; i < len; ++i) {
    view.setUint32(i * 8, data[i][0]);
    view.setUint32(i * 8 + 4, data[i][1]);
  }
  return new Uint8Array(buff);
}

function createCipher(cipherAlgo, key) {
  var len = key.length;
  var buff = createArrayBuffer(key);
  var view = new DataView(buff);
  key = new Array(len / 4);
  for (var i = 0; i < len / 4; ++i) {
    key[i] = view.getUint32(i * 4);
  }
  return new AES(key);
}

// RFC 3394 2.2.1 Key Wrap
function wrap(cipherAlgo, key, data) {
  var IV = new Uint32Array([0xA6A6A6A6, 0xA6A6A6A6]);
  var aes = createCipher(cipherAlgo, key);
  var P = unpack(data);
  var A = IV;
  var R = P;
  var n = P.length;
  var t = new Uint32Array([0, 0]);
  for (var j = 0; j <= 5; ++j) {
    for (var i = 0; i < n; ++i) {
      t[1] = n * j + (1 + i);
      var B = new Uint32Array(4);
      // B = A
      B[0] = A[0];
      B[1] = A[1];
      // B = A || R[i]
      B[2] = R[i][0];
      B[3] = R[i][1];
      // B = AES(K, B)
      B = aes.encrypt(B);
      // A = MSB(64, B) ^ t
      A = B.subarray(0, 2);
      A[0] = A[0] ^ t[0];
      A[1] = A[1] ^ t[1];
      // R[i] = LSB(64, B)
      R[i] = B.subarray(2, 4);
    }
  }
  return pack([A].concat(R));
}

// RFC 3394 2.2.2 Key Unwrap
function unwrap(cipherAlgo, key, data) {
  var IV = new Uint32Array([0xA6A6A6A6, 0xA6A6A6A6]);
  var aes = createCipher(cipherAlgo, key);
  var C = unpack(data);
  var A = C[0];
  var R = C.slice(1);
  var n = C.length - 1;
  var t = new Uint32Array([0, 0]);
  for (var j = 5; j >= 0; --j) {
    for (var i = n - 1; i >= 0; --i) {
      t[1] = n * j + (i + 1);
      var B = new Uint32Array(4);
      // B = A ^ t
      B[0] = A[0] ^ t[0];
      B[1] = A[1] ^ t[1];
      // B = (A ^ t) || R[i]
      B[2] = R[i][0];
      B[3] = R[i][1];
      // B = AES-1(B)
      B = aes.decrypt(B);
      // A = MSB(64, B)
      A = B.subarray(0, 2);
      // R[i] = LSB(64, B)
      R[i] = B.subarray(2, 4);
    }
  }
  if (A[0] == IV[0] && A[1] == IV[1]) {
    return pack(R);
  }
  throw new Error("Key Data Integrity failed");
}

module.exports = {
  wrap: wrap,
  unwrap: unwrap
};
