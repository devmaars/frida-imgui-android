lib: build
	$(shell pwd)/build.sh lib

java: build
	$(shell pwd)/build.sh java

all: build
	$(shell pwd)/build.sh all

clean:
	mkdir -p $(TEMP_DIR)

.PHONY: build lib java clean
