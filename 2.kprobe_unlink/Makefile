# 工具设置
GO ?= go

# 目标文件
TARGET := kprobe_unlink
GO_GENERATED := bpf_bpfel.go bpf_bpfeb.go bpf_bpfel.o bpf_bpfeb.o

.PHONY: all build generate clean run test help

# 默认目标
all: build

# 构建程序
build: $(TARGET)

$(TARGET): generate
	@echo "Building $(TARGET)..."
	$(GO) build -o $@ .

# 生成 Go 绑定文件
generate:
	@echo "Generating Go bindings..."
	$(GO) generate

# 清理构建文件
clean:
	@echo "Cleaning..."
	rm -f $(TARGET)
	rm -f $(GO_GENERATED)

# 运行程序 (需要 root 权限)
run: $(TARGET)
	@echo "Running $(TARGET)..."
	sudo ./$(TARGET)

# 测试 (创建和删除测试文件)
test:
	@echo "Creating test file..."
	touch test_file.txt
	sleep 1
	@echo "Removing test file..."
	rm -f test_file.txt

# 帮助信息
help:
	@echo "Available targets:"
	@echo "  all       - Build program (default)"
	@echo "  build     - Build program"
	@echo "  generate  - Generate Go bindings"
	@echo "  clean     - Clean build files"
	@echo "  run       - Run program (requires root)"
	@echo "  test      - Create and remove test file"
	@echo "  help      - Show this help"

# 删除失败的目标
.DELETE_ON_ERROR: