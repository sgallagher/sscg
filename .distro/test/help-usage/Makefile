.PHONY: all install download clean

BUILT_FILES=

FILES=runtest.sh Makefile

run: $(FILES) build
	./runtest.sh

build: $(BUILT_FILES)
	chmod a+x ./runtest.sh

clean:
	rm -f *~ $(BUILT_FILES)
