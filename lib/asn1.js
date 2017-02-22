var asn1 = require('asn1.js');
var rfc5280 = require('asn1.js-rfc5280');

var RSAPrivateKey = asn1.define('RSAPrivateKey', function() {
  this.seq().obj(
    this.key('version').int(),
    this.key('modulus').int(),
    this.key('publicExponent').int(),
    this.key('privateExponent').int(),
    this.key('prime1').int(),
    this.key('prime2').int(),
    this.key('exponent1').int(),
    this.key('exponent2').int(),
    this.key('coefficient').int()
  );
});
exports.RSAPrivateKey = RSAPrivateKey;

var RSAPublicKey = asn1.define('RSAPublicKey', function() {
  this.seq().obj(
    this.key('modulus').int(),
    this.key('publicExponent').int()
  );
});
exports.RSAPublicKey = RSAPublicKey;

var GeneralName = asn1.define('GeneralName', function() {
  this.choice({
    dNSName: this.implicit(2).ia5str()
  });
});
exports.GeneralName = GeneralName;

var GeneralNames = asn1.define('GeneralNames', function() {
  this.seqof(GeneralName);
});
exports.GeneralNames = GeneralNames;

var Signature = asn1.define('Signature', function() {
  this.seq().obj(
    this.key('algorithm').seq().obj(
      this.key('algorithm').objid(),
      this.null_()
    ),
    this.key('digest').octstr()
  );
});
exports.Signature = Signature;

var IA5Str = asn1.define('IA5Str', function() {
  this.ia5str();
});
exports.IA5Str = IA5Str;

var Null = asn1.define('Null', function() {
  this.null_();
});

exports.SHA256 = [ 2, 16, 840, 1, 101, 3, 4, 2, 1 ];
exports.SHA256RSA = [ 1, 2, 840, 113549, 1, 1, 11 ];
exports.SHA512 = [ 2, 16, 840, 1, 101, 3, 4, 2, 3 ];
exports.SHA512RSA = [ 1, 2, 840, 113549, 1, 1, 13 ];
exports.RSA = [ 1, 2, 840, 113549, 1, 1, 1 ];
exports.COMMONNAME = [ 2, 5, 4, 3 ];
exports.ALTNAME = [ 2, 5, 29, 17 ];

exports.TBSCertificate = rfc5280.TBSCertificate;
exports.Certificate = rfc5280.Certificate;
exports.EMPTY_PARAMETERS = Null.encode(null, 'der');
