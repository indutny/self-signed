var bn = require('bn.js');
var brorand = require('brorand');
var mr = require('miller-rabin');
var asn1 = require('./asn1');
var rsa = require('./rsa');

var EventEmitter = require('events').EventEmitter;

function KeyGen(options) {
  this.options = options || {};
  this.rand = new brorand.Rand(this.options.prng);
  this.mr = mr.create(this.rand);
  this.sieveLimit = 0x100000;
}
module.exports = KeyGen;

KeyGen.create = function create(options) {
  return new KeyGen(options);
};

KeyGen.prototype.getPrime = function getPrime(bits, cb) {
  var self = this;
  var e = new EventEmitter();
  var aborted = false;

  e.abort = function abort() {
    aborted = true;
  };

  function next() {
    do {
      var r = self.rand.generate(Math.ceil(bits / 8));
      r[0] |= 0xc0;
      r[r.length - 1] |= 3;
      r = new bn(r);

      if (!self.simpleSieve(r))
        continue;

      e.emit('try', 'fermat');
      if (!self.fermatTest(r))
        continue;

      e.emit('try', 'miller-rabin');
      if (!self.mr.test(r))
        continue;

      e.emit('try', 'prime');
      return cb(null, r);
    } while (false);

    if (aborted)
      return cb(new Error('aborted'));
    setImmediate(next);
  }
  setImmediate(next);

  return e;
};

var primes = null;

KeyGen.prototype._getPrimes = function _getPrimes() {
  if (primes !== null)
    return primes;

  var limit = this.sieveLimit;
  var res = [];
  res[0] = 2;
  for (var i = 1, k = 3; k < limit; k += 2) {
    var sqrt = Math.ceil(Math.sqrt(k));
    for (var j = 0; j < i && res[j] <= sqrt; j++)
      if (k % res[j] === 0)
        break;

    if (i !== j && res[j] <= sqrt)
      continue;

    res[i++] = k;
  }
  primes = res;
  return res;
};

KeyGen.prototype.simpleSieve = function simpleSieve(p) {
  var primes = this._getPrimes();

  for (var i = 0; i < primes.length; i++)
    if (p.modn(primes[i]) === 0)
      return false;

  return true;
};

KeyGen.prototype.fermatTest = function fermatTest(p) {
  var red = bn.mont(p);
  return new bn(2).toRed(red).redPow(p.subn(1)).fromRed().cmpn(1) === 0;
};

KeyGen.prototype.getKeyData = function getKeyData(p, q) {
  if (p.cmp(q) === 0)
    return false;

  var p1 = p.subn(1);
  var q1 = q.subn(1);

  var phi = p1.mul(q1);
  var e = new bn(65537);
  var d = e.invm(phi);

  var exp1 = d.mod(p1);
  var exp2 = d.mod(q1);

  var lcm = p1.mul(q1).div(p1.gcd(q1));
  var check = d.mul(e).mod(lcm);
  if (check.cmpn(1) !== 0)
    return false;

  return {
    version: 0,
    modulus: p.mul(q),
    publicExponent: e,
    privateExponent: d,
    prime1: p,
    prime2: q,
    exponent1: exp1,
    exponent2: exp2,
    coefficient: q.invm(p)
  };
};

KeyGen.prototype._pemWrap = function _pemWrap(buf, label) {
  var p = buf.toString('base64');
  var out = [ '-----BEGIN ' + label + '-----' ];
  for (var i = 0; i < p.length; i += 64)
    out.push(p.slice(i, i + 64));
  out.push('-----END ' + label + '-----');
  return out.join('\n');
};

KeyGen.prototype.getPrivate = function getPrivate(data, enc) {
  var res = asn1.RSAPrivateKey.encode(data, 'der');
  if (enc !== 'pem')
    return res;

  return this._pemWrap(res, 'RSA PRIVATE KEY');
};

KeyGen.prototype.getPublic = function getPublic(data, enc) {
  var res = asn1.RSAPublicKey.encode(data, 'der');
  if (enc !== 'pem')
    return res;

  return this._pemWrap(res, 'RSA PUBLIC KEY');
};

KeyGen.prototype.getCertTBSData = function getCertTBSData(options) {
  var now = new Date();

  function ia5(str) {
    return asn1.IA5Str.encode(str, 'der');
  }

  var extensions = [];

  if (options.dnsName) {
    extensions.push({
      extnID: asn1.ALTNAME,
      critical: false,
      extnValue: asn1.GeneralNames.encode([ {
        type: 'dNSName',
        value: options.dnsName
      } ], 'der')
    });
  };

  if (options.extensions)
    extensions = extensions.concat(options.extensions);

  var oneDay = 24 *3600 * 1000;
  var tenYears = 10 * 365 * 24 * 3600 * 1000;

  return {
    version: 'v3',
    serialNumber: options.serial || 0x10001,
    signature: {
      algorithm: asn1.SHA256RSA
    },
    issuer: options.issuer ? options.issuer.tbsCertificate.subject : {
      type: 'rdn',
      value: [
        [ {
          type: asn1.COMMONNAME,
          value: ia5(options.issuerName || options.commonName)
        } ]
      ]
    },
    validity: {
      notBefore: {
        type: 'utcTime',
        value: options.notBefore || new Date(+now - oneDay)
      },
      notAfter: {
        type: 'utcTime',
        value: options.notAfter ||
               new Date(+now + (options.validity || tenYears))
      }
    },
    subject: {
      type: 'rdn',
      value: [
        [ { type: asn1.COMMONNAME, value: ia5(options.commonName) } ]
      ]
    },
    subjectPublicKeyInfo: {
      algorithm: {
        algorithm: asn1.RSA
      },
      subjectPublicKey: {
        unused: 0,
        data: this.getPublic(options.keyData)
      }
    },
    extensions: extensions
  };
};

KeyGen.prototype.getCertData = function getCertData(options) {
  var tbsData = this.getCertTBSData(options);
  var tbs = asn1.TBSCertificate.encode(tbsData, 'der');

  var signature = rsa.sign(tbs, options.issuerKeyData || options.keyData);

  return {
    tbsCertificate: tbsData,
    signatureAlgorithm: {
      algorithm: asn1.SHA256RSA
    },
    signature: { unused: 0, data: signature }
  };
};

KeyGen.prototype.getCert = function getCert(data, enc) {
  var res = asn1.Certificate.encode(data, 'der');
  if (enc !== 'pem')
    return res;

  return this._pemWrap(res, 'CERTIFICATE');
};
