BUILD_VERSION?="$(shell git for-each-ref --sort=-v:refname --count=1 --format '%(refname)'  | cut -d '/' -f3)"
OUTDIR="crowdsec-nginx-njs-bouncer-${BUILD_VERSION}/"
OUT_ARCHIVE="crowdsec-nginx-njs-bouncer.tgz"

.PHONY: clean
clean:
	rm -rf ./lib
	rm -rf "${OUTDIR}"
	rm -rf "${OUT_ARCHIVE}"

.PHONY: build
build:
	./node_modules/typescript/bin/tsc 
	cat ./src/third_party/*  ./lib/crowdsec.js > /tmp/temp  && mv /tmp/temp ./lib/crowdsec.js
	cp -r ./src/templates ./lib/

release: clean build
	mkdir -p ${OUTDIR} 

	cp -r ./lib/* ${OUTDIR}
	cp ./scripts/* ${OUTDIR}

	cp -r ./conf ${OUTDIR}
	tar cvzf ${OUT_ARCHIVE} ${OUTDIR}
