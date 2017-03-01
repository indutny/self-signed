'use strict';

const path = require('path');

const DIST = path.join(__dirname, 'dist');
const SRC = path.join(__dirname, 'src');

const loaders = [
];

module.exports = [{
  target: 'web',
  entry: path.join(SRC, 'app.js'),
  output: {
    path: DIST,
    filename: 'bundle.js'
  },
  module: {
    loaders: loaders
  }
}, {
  target: 'webworker',
  entry: path.join(SRC, 'worker.js'),
  output: {
    path: DIST,
    filename: 'worker.js'
  },
  module: {
    loaders: loaders
  }
}, {
  target: 'webworker',
  entry: path.join(SRC, 'bench.js'),
  output: {
    path: DIST,
    filename: 'bench.js'
  },
  module: {
    loaders: loaders
  }
}];
