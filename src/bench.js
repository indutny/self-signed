var prng = require('./prng');
var kg = require('../').create({ prng: prng });
var bn = require('bn.js');
var constants = require('./constants');

prng.seed(new Uint8Array(32));

var log = typeof console === 'object' ? console.log.bind(console) : print;

// Poly-fill
var tick = [];
setImmediate = function(cb) {
  tick.push(cb);
};
setTimeout = setImmediate;

var primes = 8;
function run() {
  var start = Date.now();
  kg.getPrime(1024, function(err, prime) {
    var end = Date.now();
    log(end - start);
    if (--primes > 0)
      run();
  });
}
run();

while (tick.length)
  tick.shift()();
