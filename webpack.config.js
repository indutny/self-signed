'use strict';

const path = require('path');

const DIST = path.join(__dirname, 'dist');
const SRC = path.join(__dirname, 'src');

const loaders = [
];

module.exports = [{
  entry: path.join(SRC, 'app.js'),
  output: {
    path: DIST,
    filename: 'bundle.js'
  },
  module: {
    loaders: loaders
  }
}, {
  entry: path.join(SRC, 'worker.js'),
  output: {
    path: DIST,
    filename: 'worker.js'
  },
  module: {
    loaders: loaders
  }
}];
