# Название бинарного файла
EXAMPLE_NAME=example
VERSION?=0.1.0

# Go параметры
GO=go
GOBUILD=$(GO) build
GOCLEAN=$(GO) clean
GOTEST=$(GO) test
GOGET=$(GO) get
GOMOD=$(GO) mod

# Пути
SRC_DIR=./cmd/example
BUILD_DIR=./bin

# Флаги сборки
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(shell date +%FT%T%z)"

.PHONY: all build clean test run install uninstall fmt vet lint docker-build help

all: build

## build: Скомпилировать пример
build:
	$(GOBUILD) -C $(SRC_DIR) $(LDFLAGS) -o $(BUILD_DIR)/$(EXAMPLE_NAME)

## clean: Удалить скомпилированные файлы
clean:	
	$(GOCLEAN)
	rm -rf $(SRC_DIR)/bin
## rm -rf cmd/example/bin	
	
## test: Запустить тесты
test:
	$(GOTEST) ./... -v -cover -count=1

## fmt: Форматировать исходный код
fmt:
	$(GO) fmt ./...

## vet: Проверить код на наличие подозрительных конструкций
vet:
	$(GO) vet ./...

## lint: Запустить линтер (golangci-lint)
lint:
	golangci-lint run ./...

## help: Показать справку по командам
help:
	@echo "Доступные команды:"
	@echo
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'
	@echo