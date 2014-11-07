var hash = require('hash.js');
var brorand = require('brorand');
var bn = require('bn.js');
var asn1 = require('./asn1');

exports.sign = function sign(data, keyData) {
  var toSign = new hash.sha256().update(data).digest();

  toSign = asn1.Signature.encode({
    algorithm: {
      algorithm: asn1.SHA256
    },
    digest: toSign
  }, 'der');

  var len = keyData.modulus.byteLength();

  // PKCS1 padding
  var pad = [ 0, 1 ];

  while (toSign.length + pad.length + 1 < len)
    pad.push(0xff);
  pad.push(0x00);

  for (var i = 0; i < toSign.length; i++)
    pad.push(toSign[i]);
  toSign = pad;

  var red = bn.mont(keyData.modulus);
  toSign = new bn(toSign).toRed(red);

  toSign = toSign.redPow(keyData.privateExponent);

  return toSign.fromRed().toArray();
};
