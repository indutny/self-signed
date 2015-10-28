var KG = require('../');
var assert = require('assert');

describe('Self-Signed', function() {
  var kg;
  beforeEach(function() {
    kg = KG.create();
  });

  it('should generate prime numbers', function(cb) {
    var ev = kg.getPrime(256, function(err, p) {
      if (err)
        throw err;

      assert.equal(p.bitLength(), 256);
      cb();
    });

    ev.on('try', function(type) {
      if (type === 'miller-rabin')
        process.stdout.write('.');
      else if (type === 'prime')
        process.stdout.write('+');
    });
  });

  it('should generate prime numbers synchronously', function() {
    var p = kg.getPrime(256);
    assert.equal(p.bitLength(), 256);
  });

  it('should generate private key and cert', function(cb) {
    function find() {
      kg.getPrime(512, function(err, p) {
        if (err)
          throw err;
        kg.getPrime(512, function(err, q) {
          if (err)
            throw err;

          var data = kg.getKeyData(p, q);
          if (!data)
            return find();

          console.log(kg.getPrivate(data, 'pem'));

          var certData = kg.getCertData({
            commonName: 'self.signed',
            keyData: data
          });
          console.log(kg.getCert(certData, 'pem'));

          cb();
        });
      });
    }

    find();
  });
});
