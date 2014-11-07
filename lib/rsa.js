var hash = require('hash.js');
var brorand = require('brorand');
var bn = require('bn.js');

exports.sign = function sign(data, keyData) {
  var toSign = new hash.sha256().update(data).digest();
  var len = keyData.modulus.byteLength();

  // PKCS1 padding
  toSign.push(0, 1);

  while ((toSign.length + 1) % len !== 0)
    toSign.push(0xff);
  toSign.push(0x00);

  var red = bn.mont(keyData.modulus);
  toSign = new bn(toSign).toRed(red);

  toSign = toSign.redPow(keyData.privateExponent);

  return toSign.fromRed().toArray();
};
