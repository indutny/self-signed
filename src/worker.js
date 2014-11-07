var kg = require('../').create({ prng: require('./prng') });
var bn = require('bn.js');
var constants = require('./constants');

// Poly-fill
setImmediate = function(cb) {
  setTimeout(cb, 0);
};

function onTry(type) {
  if (type === 'fermat')
    postMessage(constants.worker.fermat);
  else if (type === 'miller-rabin')
    postMessage(constants.worker.miller);
  else if (type === 'prime')
    postMessage(constants.worker.prime);
}

var generators = [];

onmessage = function onmessage(e) {
  var msg = e.data;

  if (msg.type === 'generate') {
    var gen = kg.getPrime(msg.size, function(err, prime) {
      generators.splice(generators.indexOf(gen), 1);

      // Canceled
      if (err)
        return;

      postMessage(prime.toString(16));
    }).on('try', onTry);
    generators.push(gen);
    return;
  } else if (msg.type === 'cert') {
    genCert(msg.input, function(res) {
      if (res)
        postMessage(res);
      else
        postMessage(constants.worker.noCert);
    });
  } else if (msg.type === 'abort') {
    generators.forEach(function(gen) {
      gen.abort();
    });
  }
};

function genCert(input, cb) {
  var p = new bn(input.p, 16);
  var q = new bn(input.q, 16);

  var keyData = kg.getKeyData(p, q);
  if (!keyData)
    return cb(false);

  var certData = kg.getCertData({
    keyData: keyData,
    commonName: input.commonName,
    dnsName: input.dnsName
  });

  cb({
    key: kg.getPrivate(keyData, 'pem'),
    cert: kg.getCert(certData, 'pem')
  });
}
