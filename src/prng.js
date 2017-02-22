var hash = require('hash.js');
var HmacDRBG = require('hmac-drbg');
var drbg = null;

exports.seed = function seed(seed) {
  drbg = new HmacDRBG({
    hash: hash.sha512,
    entropy: seed,
    nonce: 'self-signed',
    nonceEnc: 'utf8'
  });

  exports.getBytes = function getBytes(n) {
    return drbg.generate(n);
  };
};

// Fallback
exports.getByte = function getByte() {
  return (Math.random() * 256) | 0;
};
