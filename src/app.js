var constants = require('./constants');
var Clipboard = require('clipboard');

var copy = document.querySelectorAll('.copy');
var clipboard = new Clipboard(copy);

copy.forEach(function(e) {
  e.disabled = true;
});

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
  cert: document.getElementById('cert'),
  node: document.getElementById('node')
};

function createWorker() {
  var worker = new Worker('dist/worker.js');
  if (window.crypto && window.crypto.getRandomValues) {
    var entropy = new Uint8Array(24);
    window.crypto.getRandomValues(entropy);
    worker.postMessage({ type: 'seed', seed: entropy });
  }
  return worker;
}

var workers = [];
var cores = window.navigator && window.navigator.hardwareConcurrency || 4;
for (var i = 0; i < cores; i++)
  workers.push(createWorker());

var generator = createWorker();

form.elem.onsubmit = function(e) {
  e.preventDefault();

  if (form.disabled)
    return;

  form.disabled = true;
  form.elems.forEach(function(elem) {
    elem.disabled = true;
  });
  copy.forEach(function(e) {
    e.disabled = true;
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
    out.node.value = 'const options = {\n' +
                     '  key: ' + JSON.stringify(res.key) + ',\n' +
                     '  cert: ' + JSON.stringify(res.cert) + '\n' +
                     '};\n';

    out.progress.all.value = 100;
    out.progress.prime.value = 100;

    copy.forEach(function(e) {
      e.disabled = false;
    });
  });

};

function run(input, cb) {
  var abort = sievePrimes(input.size >> 1, function(p, q) {
    generator.postMessage({
      type: 'cert',
      input: {
        commonName: input.commonName,
        dnsName: input.wildcard ? '*.' + input.commonName : false,
        p: p,
        q: q
      }
    });
  });

  generator.onmessage = function(e) {
    var data = e.data;

    // Check that this is not a progress report
    if (typeof data === 'number')
      return;

    abort();
    cb(data);
  };
}

function sievePrimes(size, cb) {
  var prev = null;
  var done = false;
  var gen = { type: 'generate', size: size };

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

      var prime = response;
      if (prev !== null)
        cb(prev, prime);
      prev = prime;

      // Continue searching
      worker.postMessage(gen);
    };
    worker.postMessage(gen);
  });

  return function abort() {
    if (done)
      return;
    done = true;

    workers.forEach(function(worker) {
      worker.postMessage({ type: 'abort' });
    });
  }
}
