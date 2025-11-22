.PHONY: build test scan clean

IMAGE_NAME := git-security-scanner
VERSION := latest

build:
	docker build -t $(IMAGE_NAME):$(VERSION) .

test:
	python3 -m unittest discover tests

scan:
	docker run --rm \
		-v $$(pwd):/scan_target \
		-v $$(pwd)/reports:/reports \
		$(IMAGE_NAME):$(VERSION) all

clean:
	rm -rf reports
	rm -rf __pycache__
	rm -rf tests/__pycache__
