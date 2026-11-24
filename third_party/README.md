# third_party — Full 版外部程序

本目录只保存清单/说明，**不提交 UnRAR/hashcat 二进制**。

Windows Full 安装包在发布流水线中按 `manifest.json`（W4 建立）获取：

```text
third_party/unrar/UnRAR.exe   # 未修改，附 license.txt
third_party/hashcat/          # 固定版本，附 MIT/第三方声明
```

规则：

- 固定版本、来源 URL、SHA-256；构建/发布按清单取包，运行时不在线更新。
- UnRAR 只作为独立进程；不链接、不调用 `unrar.dll`、不复制源码。
- hashcat 只作为独立进程；不加入 Cargo 依赖，不复制内核。
- 不随包 WinRAR、CUDA/HIP/OpenCL 运行时或 GPU 驱动。
- 见 `docs/adr/0004-bundled-engines.md`、`docs/licensing.md`。
