TARGETS := $(shell ls scripts)

.dapper:
	@echo Downloading dapper
	@curl -sL https://releases.rancher.com/dapper/latest/dapper-`uname -s`-`uname -m` > .dapper.tmp
	@@chmod +x .dapper.tmp
	@./.dapper.tmp -v
	@mv .dapper.tmp .dapper

$(TARGETS): .dapper
	./.dapper $@

.DEFAULT_GOAL := ci

.PHONY: $(TARGETS) dev clean

dev:
	mkdir -p bin
	CGO_ENABLED=0 go build -o bin/k8s-net-attach-def-controller

clean:
	rm -rf bin/ dist/

image: ci
	docker push cnrancher/k8s-net-attach-def-controller:latest

shell-bind: .dapper
	./.dapper -m bind -s

