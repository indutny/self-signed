SRC = $(wildcard lib/*.js)

all: dist/bundle.js dist/worker.js

dist/bundle.js: src/app.js $(SRC)
	./node_modules/.bin/browserify $< -o $@

dist/worker.js: src/worker.js $(SRC)
	./node_modules/.bin/browserify --ignore crypto $< -o $@

.PHONY: all
