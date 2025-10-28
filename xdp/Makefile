IFNAME ?= "enp60s0"

generate:
	go generate ./...

build: generate
	go build .

run: build
	sudo ./xdp -ifname $(IFNAME)