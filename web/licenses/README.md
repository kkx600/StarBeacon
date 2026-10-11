# 前端依赖许可

两端生产构建使用 Vite 的 `build.license`，按实际打包依赖生成 `dist/third-party-licenses.json`，再由 `scripts/complete-licenses.mjs` 校对身份、原文、版本及摘要。该目录不包含仅安装但未打包的依赖，不能替代完整 SBOM。[Vite 构建许可目录](https://vite.dev/config/build-options.html#build-license)

部分上游 npm 制品未附带许可原文。补充文本必须依据该发布版本在 npm 元数据中登记的 `gitHead`，读取对应上游仓库的 LICENSE；不能仅凭相同 SPDX 标识使用其它版本或项目的文本。`sources.json` 保存包版本、上游提交、元数据 URL、原文 URL 与 SHA-256。构建过程不访问网络，也不改写 `node_modules`。

| 包 | 版本 | 上游许可 |
| --- | --- | --- |
| `@ant-design/icons-svg` | `4.6.0` | [发布提交的 LICENSE](https://github.com/ant-design/ant-design-icons/blob/7f2516ac91226d2b41f93b35cb5197c8d94f7189/LICENSE) |
| `@ant-design/icons-vue` | `7.0.1` | [发布提交的 LICENSE](https://github.com/ant-design/ant-design-icons/blob/a8b4733c27d0c49efe298e4a30146af0d91b10b3/LICENSE) |

版本错配、缺少身份或原文、重复依赖、符号链接、越界路径及摘要变化会阻止构建。只有整个目录通过校对后才替换输出文件。许可证原文保留上游的版权归属与语言，不作为产品业务文案翻译。

Linux ZIP 内的 `manifest.json` 绑定项目 LICENSE 和前端许可目录的摘要与依赖版本数；包校验器还核对目录内每份原文摘要。五个 Go 程序另有逐程序 CycloneDX SBOM、许可原文、运行时许可与所需编译源码交付，详见 [Go 依赖与发行交付](../../docs/Go依赖与发行交付.md)。两类目录独立验证，前端许可校对不能替代 Go 依赖或完整供应链验收。
