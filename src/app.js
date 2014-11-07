var bn = require('bn.js');
var kg = require('../').create();
var constants = require('./constants');

var form = {
  disabled: false,
  elem: document.getElementsByTagName('form')[0],
  inputs: {
    size: document.getElementById('size'),
    commonName: document.getElementById('cn'),
    wildcard: document.getElementById('wildcard'),
    submit: document.getElementById('submit')
  },
  elems: []
};

form.elems.push(form.elem, form.inputs.size, form.inputs.commonName,
                form.inputs.wildcard, form.inputs.submit);

var out = {
  progress: {
    all: document.getElementById('progress-all'),
    prime: document.getElementById('progress-prime')
  },
  key: document.getElementById('key'),
  cert: document.getElementById('cert')
};

var workers = [];
for (var i = 0; i < 4; i++)
  workers.push(new Worker('/dist/worker.js'));

form.elem.onsubmit = function(e) {
  e.preventDefault();

  if (form.disabled)
    return;

  form.disabled = true;
  form.elems.forEach(function(elem) {
    elem.disabled = true;
  });
  out.progress.all.value = 0;
  out.progress.prime.value = 0;

  run({
    size: form.inputs.size.value | 0,
    commonName: form.inputs.commonName.value,
    wildcard: form.inputs.wildcard.value
  }, function(res) {
    form.disabled = false;
    form.elems.forEach(function(elem) {
      elem.disabled = false;
    });

    out.key.value = res.key;
    out.cert.value = res.cert;
    out.progress.all.value = 100;
    out.progress.prime.value = 100;
  });

};

function run(input, cb) {
  sievePrimes(input.size >> 1, function(p, q) {
    var keyData = kg.getKeyData(p, q);
    if (!keyData)
      return false;

    // Do not block sievePrimes
    setTimeout(function() {
      var certData = kg.getCertData({
        commonName: input.commonName,
        dnsName: input.wildcard ? '*.' + input.commonName : false,
        keyData: keyData
      });

      cb({
        key: kg.getPrivate(keyData, 'pem'),
        cert: kg.getCert(certData, 'pem')
      });
    }, 0);

    return true;
  });
}

function sievePrimes(size, cb) {
  var prev = null;
  var done = false;
  workers.forEach(function(worker) {
    worker.onmessage = function onmessage(e) {
      var response = e.data;
      if (done)
        return;

      // Just a progress report
      if (typeof response !== 'string') {
        if (response === constants.prime)
          out.progress.prime.value = ((out.progress.prime.value | 0) + 1) % 10;
        else
          out.progress.all.value = ((out.progress.all.value | 0) + 1) % 100;
        return;
      }

      var prime = new bn(response, 16);
      if (prev !== null) {
        done = cb(prev, prime);

        if (done) {
          workers.forEach(function(worker) {
            worker.postMessage({ type: 'abort' });
          });
        }
      }
      prev = prime;

      // Continue searching
      if (!done)
        worker.postMessage({ type: 'generate', size: size });
    };
    worker.postMessage({ type: 'generate', size: size });
  });
}
