BUILD_PATH?=../build

.PHONY: test
test:
	sudo env BUILD_PATH=${BUILD_PATH} bundle exec cucumber

.PHONY: bootstrap
bootstrap:
	bundle config set path 'vendor/bundle'
	bundle install
