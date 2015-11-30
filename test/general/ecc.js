'use strict';

var openpgp = typeof window != 'undefined' && window.openpgp ? window.openpgp : require('openpgp');

var chai = require('chai'),
  expect = chai.expect;

describe('Elliptic Curve Cryptography', function () {
  var data = {
    romeo: {
      id: 'c2b12389b401a43d',
      pass: 'juliet',
      pub: [
        '-----BEGIN PGP PUBLIC KEY BLOCK-----',
        'Version: OpenPGP.js 1.3+secp256k1',
        'Comment: http://openpgpjs.org',
        '',
        'xk8EVjET2xMFK4EEAAoCAwS/zT2gefLhEnISXN3rvdV3eD6MVrPwxNMAR+LM',
        'ZzFO1gdtZbf7XQSZP02CYQe3YFrNQYYuJ4CGkTvOVJSV+yrAzS5Sb21lbyBN',
        'b250YWd1ZSAoc2VjcDI1NmsxKSA8cm9tZW9AZXhhbXBsZS5uZXQ+wnIEEBMI',
        'ACQFAlYxE9sFCwkIBwMJEMKxI4m0AaQ9AxUICgMWAgECGwMCHgEAAOjHAQDM',
        'y6EJPFayCgI4ZSmZlSue3xFShj9y6hZTLZqPJquspQD+MMT00a2Cicnbhrd1',
        '8SQUIYRQ//I7oXVoxZN5MA4rmOHOUwRWMRPbEgUrgQQACgIDBLPZgGC257Ra',
        'Z9Bg3ij9OgSoJGwqIu03SfQMTnR2crHkAHqLaUImz/lwhsL/V499zXZ2gEmf',
        'oKCacroXNDM85xUDAQgHwmEEGBMIABMFAlYxE9sJEMKxI4m0AaQ9AhsMAADk',
        'gwEA4B3lysFe/3+KE/PgCSZkUfx7n7xlKqMiqrX+VNyPej8BAMQJgtMVdslQ',
        'HLr5fhoGnRots3JSC0j20UQQOKVOXaW3',
        '=VpL9',
        '-----END PGP PUBLIC KEY BLOCK-----'].join('\n'),
      priv: [
        '-----BEGIN PGP PRIVATE KEY BLOCK-----',
        'Version: OpenPGP.js 1.3+secp256k1',
        'Comment: http://openpgpjs.org',
        '',
        'xaIEVjET2xMFK4EEAAoCAwS/zT2gefLhEnISXN3rvdV3eD6MVrPwxNMAR+LM',
        'ZzFO1gdtZbf7XQSZP02CYQe3YFrNQYYuJ4CGkTvOVJSV+yrA/gkDCILD3FP2',
        'D6eRYNWhI+QTFWAGDw+pIhtXQ/p0zZgK6HSk68Fox0tH6TlGtPmtULkPExs0',
        'cnIdAVSMHI+SnZ9lIeAykAcFoqJYIO5p870XbjzNLlJvbWVvIE1vbnRhZ3Vl',
        'IChzZWNwMjU2azEpIDxyb21lb0BleGFtcGxlLm5ldD7CcgQQEwgAJAUCVjET',
        '2wULCQgHAwkQwrEjibQBpD0DFQgKAxYCAQIbAwIeAQAA6McBAMzLoQk8VrIK',
        'AjhlKZmVK57fEVKGP3LqFlMtmo8mq6ylAP4wxPTRrYKJyduGt3XxJBQhhFD/',
        '8juhdWjFk3kwDiuY4cemBFYxE9sSBSuBBAAKAgMEs9mAYLbntFpn0GDeKP06',
        'BKgkbCoi7TdJ9AxOdHZyseQAeotpQibP+XCGwv9Xj33NdnaASZ+goJpyuhc0',
        'MzznFQMBCAf+CQMIqp5StLTK+lBgqmaJ8/64E+8+OJVOgzk8EoRp8bS9IEac',
        'VYu2i8ARjAF3sqwGZ5hxxsniORcjQUghf+n+NwEm9LUWfbAGUlT4YfSIq5pV',
        'rsJhBBgTCAATBQJWMRPbCRDCsSOJtAGkPQIbDAAA5IMBAOAd5crBXv9/ihPz',
        '4AkmZFH8e5+8ZSqjIqq1/lTcj3o/AQDECYLTFXbJUBy6+X4aBp0aLbNyUgtI',
        '9tFEEDilTl2ltw==',
        '=C3TW',
        '-----END PGP PRIVATE KEY BLOCK-----'].join('\n'),
      message: 'Shall I hear more, or shall I speak at this?'
    },
    juliet: {
      id: '64116021959bdfe0',
      pass: 'romeo',
      pub: [
        '-----BEGIN PGP PUBLIC KEY BLOCK-----',
        'Version: OpenPGP.js 1.3+secp256k1',
        'Comment: http://openpgpjs.org',
        '',
        'xk8EVjEUUBMFK4EEAAoCAwQRNz0sbftAv3SSE0fm7vE0pD96NDA3YtGdObaj',
        'D0DNUMBL1eoLl5/qdJUc/16xbZLkL2saMsbqtPn/iuahz6bkzS9KdWxpZXQg',
        'Q2FwdWxldCAoc2VjcDI1NmsxKSA8anVsaWV0QGV4YW1wbGUubmV0PsJyBBAT',
        'CAAkBQJWMRRRBQsJCAcDCRBkEWAhlZvf4AMVCAoDFgIBAhsDAh4BAAAr1wEA',
        '+39TqKy/tks7dPlEYw+IYkFCW99a60kiSCjLBPxEgNUA/3HeLDP/XbrgklUs',
        'DFOy20aHE7M6i/cFXLLxDJmN6BF3zlMEVjEUUBIFK4EEAAoCAwTQ02rHHP/d',
        'kR4W7y5BY4kRtoNc/HxUloOpxA8svfmxwOoP5stCS/lInD8K+7nSEiPr84z9',
        'EQ47LMjiT1zK2mHZAwEIB8JhBBgTCAATBQJWMRRRCRBkEWAhlZvf4AIbDAAA',
        '7FoA/1Y4xDYO49u21I7aqjPyTygLoObdLMAtK6xht+DDc0YKAQDNp2wv0HOJ',
        '+0kjoUNu6PRIll/jMgTVAXn0Mov6HqJ95A==',
        '=ISmy',
        '-----END PGP PUBLIC KEY BLOCK-----'].join('\n'),
      priv: [
        '-----BEGIN PGP PRIVATE KEY BLOCK-----',
        'Version: OpenPGP.js 1.3+secp256k1',
        'Comment: http://openpgpjs.org',
        '',
        'xaIEVjEUUBMFK4EEAAoCAwQRNz0sbftAv3SSE0fm7vE0pD96NDA3YtGdObaj',
        'D0DNUMBL1eoLl5/qdJUc/16xbZLkL2saMsbqtPn/iuahz6bk/gkDCD9EH0El',
        '7o9qYIbX56Ri3VlfCbpQgy1cVx9RETKI4guW9vUu6SeY2NhXASvfK+zgpLzO',
        'j+hv2a+re549UKBdFbPEcyPUQKo2YJ1AfdAfZcDNL0p1bGlldCBDYXB1bGV0',
        'IChzZWNwMjU2azEpIDxqdWxpZXRAZXhhbXBsZS5uZXQ+wnIEEBMIACQFAlYx',
        'FFEFCwkIBwMJEGQRYCGVm9/gAxUICgMWAgECGwMCHgEAACvXAQD7f1OorL+2',
        'Szt0+URjD4hiQUJb31rrSSJIKMsE/ESA1QD/cd4sM/9duuCSVSwMU7LbRocT',
        'szqL9wVcsvEMmY3oEXfHpgRWMRRQEgUrgQQACgIDBNDTascc/92RHhbvLkFj',
        'iRG2g1z8fFSWg6nEDyy9+bHA6g/my0JL+UicPwr7udISI+vzjP0RDjssyOJP',
        'XMraYdkDAQgH/gkDCA4aIC5h7thWYEM9KvwVEN4/rAYOWVNzUN2K7l25M+NZ',
        '1/mEAjEgEW9yPufKtF3hILeNdPBwh6Gcw/0gOJ/9yJwKk7tqwyS/gKF1+VDm',
        'X0LCYQQYEwgAEwUCVjEUUQkQZBFgIZWb3+ACGwwAAOxaAP9WOMQ2DuPbttSO',
        '2qoz8k8oC6Dm3SzALSusYbfgw3NGCgEAzadsL9BziftJI6FDbuj0SJZf4zIE',
        '1QF59DKL+h6ifeQ=',
        '=QvXN',
        '-----END PGP PRIVATE KEY BLOCK-----'].join('\n'),
      message: 'O Romeo, Romeo! Wherefore art thou Romeo?',
      message_signed: [
        '-----BEGIN PGP SIGNED MESSAGE-----',
        'Hash: SHA256',
        '',
        'O Romeo, Romeo! Wherefore art thou Romeo?',
        '-----BEGIN PGP SIGNATURE-----',
        'Version: GnuPG v2',
        'Comment: GnuPG v2.1+libgcrypt-1.7',
        '',
        'iF4EARMIAAYFAlYxF8oACgkQZBFgIZWb3+BfTwD/b1yKtFnKrRjELuD6/gOH9/er',
        '6yc7nzn1FBYFzMz8aFIA/3FlcIvR+eLvRTVmfiEatB6IU6JviBnzxR1gA/SOdyS2',
        '=GCiR',
        '-----END PGP SIGNATURE-----'].join('\n'),
      message_encrypted: [
        '-----BEGIN PGP MESSAGE-----',
        'Version: GnuPG v2',
        'Comment: GnuPG v2.1+libgcrypt-1.7',
        '',
        'hH4DDYFqRW5CSpsSAgMERfIYgKzriOCHTTQnWhM4VZ6cLjrjJbOaW1VuCfeN03d+',
        'yzhW1Sm1BYYdqxPE0rvjvGfD8VmMB6etaHQsrDQflzA+vGeVa9Mn/wyKq4+j13ur',
        'NOoUhDKX27+LEBNfho6bbEN72J7z3E5/+wVr+wEt3bLSwBcBvuNNkvGCpE19/AmL',
        'GP2lmjE6O9VfiW0o8sxfa+hPEq2A+6DxvMhxi2YPS0f9MMPqn5NFx2PCIGdC0+xY',
        'f0BXl1atBO1z6UXTC9aHH7UULKdynr4nUEkDa3DJW/feCSC6rQxTikn/Gf4341qQ',
        'aiwv66jhgJSdB+2+JrHfh6Znvv2fhl3SQl8K0CiG8Q0QubWdlQwNaNSOmgH7v3T8',
        'j5FhrMbD3Z+TPlrNjJqidAV28XwSBFvhw8Jf5WpaewOxVlxLjUHnnkUGHyvfdEr/',
        'DP/V1yLuBUZuRg==',
        '=GEAB',
        '-----END PGP MESSAGE-----'].join('\n')
    }
  };
  function load_pub_key(name) {
    if (data[name].pub_key)
      return data[name].pub_key;
    var pub = openpgp.key.readArmored(data[name].pub);
    expect(pub).to.exist;
    expect(pub.err).to.not.exist;
    expect(pub.keys).to.have.length(1);
    expect(pub.keys[0].primaryKey.getKeyId().toHex()).to.equal(data[name].id);
    data[name].pub_key = pub.keys[0];
    return data[name].pub_key;
  }
  function load_priv_key(name) {
    if (data[name].priv_key)
      return data[name].priv_key;
    var pk = openpgp.key.readArmored(data[name].priv);
    expect(pk).to.exist;
    expect(pk.err).to.not.exist;
    expect(pk.keys).to.have.length(1);
    expect(pk.keys[0].primaryKey.getKeyId().toHex()).to.equal(data[name].id);
    expect(pk.keys[0].decrypt(data[name].pass)).to.be.true;
    data[name].priv_key = pk.keys[0];
    return data[name].priv_key;
  }
  it('Load public key', function (done) {
    load_pub_key('romeo');
    load_pub_key('juliet');
    done();
  });
  it('Load private key', function (done) {
    load_priv_key('romeo');
    load_priv_key('juliet');
    done();
  });
  it('Generate key pair', function (done) {
    var options = {
      userId: "Hamlet (secp256k1) <hamlet@example.net>",
      curve: "secp256k1",
      passphrase: "ophelia"
    };
    openpgp.generateKeyPair(options).then(function (keyPair) {
      expect(keyPair).to.exist;
      expect(keyPair.key).to.exist;
      expect(keyPair.key.primaryKey).to.exist;
      var r = keyPair.key.primaryKey.getFingerprint();
      expect(keyPair.privateKeyArmored).to.exist;
      expect(keyPair.publicKeyArmored).to.exist;
      done();
    });
  });
  it('Generate key pair from data', function (done) {
    var keyMaterial = openpgp.util.hex2bin("347c34c64376d079f00d5fabd0d63d12e440b948267a13a9188a4f970771477d");
    var options = {
      userId: "Horatio (secp256k1) <horatio@example.net>",
      curve: "secp256k1",
      material: {
        key: keyMaterial,
        subkey: keyMaterial
      }
    };
    openpgp.generateKeyPair(options).then(function (keyPair) {
      expect(keyPair).to.exist;
      expect(keyPair.key).to.exist;
      expect(keyPair.key.isPrivate()).to.be.true;
      expect(keyPair.key.primaryKey).to.exist;
      expect(keyPair.key.primaryKey.mpi[2].toBytes()).to.equal(keyMaterial);
      expect(keyPair.privateKeyArmored).to.exist;
      expect(keyPair.publicKeyArmored).to.exist;
      done();
    });
  });
  it('Verify clear signed message', function (done) {
    var pub = load_pub_key('juliet');
    var msg = openpgp.cleartext.readArmored(data['juliet'].message_signed);
    openpgp.verifyClearSignedMessage([pub], msg).then(function (result) {
      expect(result).to.exist;
      expect(result.text).to.equal(data['juliet'].message);
      expect(result.signatures).to.have.length(1);
      expect(result.signatures[0].valid).to.be.true;
      done();
    });
  });
  it('Sign message', function (done) {
    var romeo = load_priv_key('romeo');
    openpgp.signClearMessage([romeo], data['romeo'].message + "\n").then(function (signedMessage) {
      var romeo = load_pub_key('romeo');
      var clearMessage = openpgp.cleartext.readArmored(signedMessage);
      openpgp.verifyClearSignedMessage([romeo], clearMessage).then(function (result) {
        expect(result).to.exist;
        expect(result.text.trim()).to.equal(data['romeo'].message);
        expect(result.signatures).to.have.length(1);
        expect(result.signatures[0].valid).to.be.true;
        done();
      });
    });
  });
  it('Decrypt and verify message', function (done) {
    var juliet = load_pub_key('juliet');
    var romeo = load_priv_key('romeo');
    var msg = openpgp.message.readArmored(data['juliet'].message_encrypted);
    openpgp.decryptAndVerifyMessage(romeo, [juliet], msg).then(function (result) {
      expect(result).to.exist;
      // trim required because https://github.com/openpgpjs/openpgpjs/issues/311
      expect(result.text.trim()).to.equal(data['juliet'].message);
      expect(result.signatures).to.have.length(1);
      expect(result.signatures[0].valid).to.be.true;
      done();
    });
  });
  it('Encrypt and sign message', function (done) {
    var romeo = load_priv_key('romeo');
    var juliet = load_pub_key('juliet');
    openpgp.signAndEncryptMessage([juliet], romeo, data['romeo'].message + "\n").then(function (encryptedSignedMessage) {
      var message = openpgp.message.readArmored(encryptedSignedMessage);
      var romeo = load_pub_key('romeo');
      var juliet = load_priv_key('juliet');
      openpgp.decryptAndVerifyMessage(juliet, [romeo], message).then(function (result) {
        expect(result).to.exist;
        expect(result.text.trim()).to.equal(data['romeo'].message);
        expect(result.signatures).to.have.length(1);
        expect(result.signatures[0].valid).to.be.true;
        done();
      });
    });
  });
});

function das() {
  throw new Error('Not valid curve');
}

describe('ECC parameters validation', function () {
  var verify_signature = function (oid, r, s, pub, message) {
    return function () {
      var signature = [];
      signature.push(new openpgp.MPI());
      signature[0].fromBytes(r);
      signature.push(new openpgp.MPI());
      signature[1].fromBytes(s);
      var publicKey = [];
      publicKey.push({ oid: oid });
      publicKey.push(new openpgp.MPI());
      publicKey[1].fromBytes(pub);
      return openpgp.crypto.signature.verify(19, // ECDSA
        8, //  SHA256
        signature,
        publicKey,
        message
      );
    }
  };
  function Oid(oid) {
    this.oid = oid || '';
  }
  Oid.prototype.write = function () {
    var bytes = String.fromCharCode(this.oid.length);
    bytes += this.oid;
    return bytes;
  };
  function KdfParams(hash, cipher) {
    this.hash = hash || enums.hash.sha1;
    this.cipher = cipher || enums.symmetric.aes128;
  }
  KdfParams.prototype.write = function () {
    var res = [];
    res[0] = 3;
    res[1] = 1;
    res[2] = this.hash;
    res[3] = this.cipher;
    return openpgp.util.bin2str(res);
  };
  var decrypt_message = function (oid, hash, cipher, priv, ephemeral, encryptionKeyData, fingerprint) {
    return function () {
      var privateKey = [];
      privateKey.push(new Oid(oid));
      privateKey.push('');
      privateKey.push(new KdfParams(hash, cipher));
      privateKey.push(new openpgp.MPI());
      privateKey[3].fromBytes(priv);
      var data = [];
      data.push(new openpgp.MPI());
      data[0].fromBytes(ephemeral);
      data.push({ data: encryptionKeyData });
      return openpgp.crypto.publicKeyDecrypt('ecdh',
        privateKey,
        data,
        fingerprint
      );
    }
  };
  var secp256k1_value = openpgp.util.bin2str([
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
  var secp256k1_point = String.fromCharCode(0x04) + openpgp.util.bin2str([
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) + openpgp.util.bin2str([
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

  it('ECDSA Invalid curve oid', function (done) {
    var res = verify_signature('invalid oid', '', '', '', '');
    expect(res).to.throw(Error, /Not valid curve/);
    res = verify_signature(openpgp.util.bin2str([0x00]), '', '', '', '');
    expect(res).to.throw(Error, /Not valid curve/);
    done();
  });
  it('ECDSA Invalid public key', function (done) {
    var res = verify_signature('secp256k1', '', '', '', '');
    expect(res).to.throw(Error, /Unknown point format/);
    var pub = String.fromCharCode(0x04) + openpgp.util.bin2str([
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    res = verify_signature('secp256k1', '', '', pub, '');
    expect(res).to.throw(Error, /Unknown point format/);
    done();
  });
  it('ECDSA Invalid signature', function (done) {
    var pub = secp256k1_point;
    var res = verify_signature('secp256k1', '', '', pub, '');
    expect(res()).to.be.false;
    done();
  });
  it('ECDH Invalid curve oid', function (done) {
    var res = decrypt_message('', 2 /* SHA1 */, 7 /* AES128 */, '', '', '', '');
    expect(res).to.throw(Error, /Not valid curve/);
    done();
  });
  it('ECDH Invalid ephemeral key', function (done) {
    var res = decrypt_message('secp256k1', 2, 7, '', '', '', '');
    expect(res).to.throw(Error, /Unknown point format/);
    done();
  });
  it('ECDH Invalid key data integrity', function (done) {
    var C = openpgp.util.bin2str([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    var res = decrypt_message('secp256k1', 2, 7, secp256k1_value, secp256k1_point, C, '');
    expect(res).to.throw(Error, /Key Data Integrity failed/);
    done();
  });
});
