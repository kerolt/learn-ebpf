# learn-ebpf

学习资料、代码来源：

- [Eunomia Tutorials](https://eunomia.dev/zh/tutorials/)
- [cilium/ebpf example](https://github.com/cilium/ebpf/blob/main/examples/)
- ...

## 安装依赖

- Fedora

    ```sh
    sudo dnf install clang llvm libbpf libbpf-devel bpftool go
    ```

## 生成 vmlinux.h

```sh
./vmlinux/update.sh
```

## 安装 cilium/ebpf

```sh
go mod tidy
```

## 运行

进入某个目录后，

```sh
go generate
sudo go run .
```
