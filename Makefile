SHELL := /bin/bash

QS=compilation_level=SIMPLE_OPTIMIZATIONS&output_format=text
URL=http://closure-compiler.appspot.com/compile
CODE=js_code@proxy.js

CHECK=\033[32m✔\033[39m

closure: proxy.js
	@echo -n "Building proxy.dist.js...                  "
	@closure proxy.js -o proxy.dist.js
	@echo -e "${CHECK} Done"

compile: proxy.js
	@mkdir -p build
	@echo -n "Building proxy.dist.js...                  "
	@curl --silent --show-error --data-urlencode "${CODE}" --data "${QS}&output_info=compiled_code" ${URL} -o proxy.dist.js
	@echo -e "${CHECK} Done"
	@echo -n "Getting compression stats...                        "
	@echo -e "${CHECK} Done\n\n" "`curl --silent --show-error --data-urlencode "${CODE}" --data "${QS}&output_info=statistics" ${URL}`"
	@echo ${STATS}

clean:
	rm -rf build
	rm -f proxy.dist.js

.PHONY: clean
