# sec-tls-verify

## 题面

客户端接自签证书后一切正常，换了张过期证书照样连得上：通配主机名把点号也匹配进去，两级子域被当成一级子域；主机名用后缀比较，evil-example.com 能命中 example.com；有效期只比较起始时间，过期证书照样通过；有效期按字符串比较日期，跨月顺序错；证书解析不读主体备用名称，只认通用名；链校验只要链里出现任意受信根就通过，不校验顺序与签名关系；链校验允许自签证书直接充当受信根；指纹只哈希序列号，不同证书可能得到同一指纹；固定校验用前缀比较指纹，短前缀也能通过；批量校验复用上一次的解析结果，后一个连接沿用前一个连接的主机名。tls/verify.py 是核心，tests/test_verify.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

## 运行方式

在仓库根目录执行：

```powershell
cd D:\gsb-20261119\sec-tls-verify
python -m pytest tests -q
```

初始状态应恰好为：

```text
15 failed
```

15 个失败必须全部来自测试调用 `tls/verify.py` 中 `raise NotImplementedError` 的桩函数；不允许出现 collection error、import error 或 syntax error，也不允许跳过测试。修复后应为 `15 passed`。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 目录

```text
sec-tls-verify/
  README.md
  conftest.py
  .gitignore
  tls/__init__.py
  tls/verify.py
  tests/test_verify.py
```

## 约束

- 只使用标准库（`re`、`datetime`、`hashlib`）与 pytest，离线运行，不使用随机数；时间必须由调用方显式传入，不能读取系统时钟。
- `tls/verify.py` 的 8 个函数当前全部是桩，契约写在各函数 docstring 中，容差为 0：主机名按标签边界精确匹配，通配符只允许出现在最左一段且只能覆盖一级子域；有效期两端都含，必须按时间先后比较而不是按字符串比较；证书链按叶子到根的顺序校验，长度不超过 4，每一环的签发者与签名关系都必须成立，并且必须终止于显式配置的受信根；指纹覆盖整张证书而不是单个字段；固定校验必须精确相等；批量校验的每个连接互相独立。
- `tests/test_verify.py` 是不可修改的验收标准；不要改测试、加 skip/xfail、放宽断言或加 monkeypatch 来制造绿色，只实现 `tls/verify.py`。
- 不得联网，不得引入第三方依赖。

## 测试

`tests/test_verify.py` 共 15 个用例：前 10 个分别锁定题面中的 10 个缺陷（越权输入必须拒绝、合法输入必须放行），其余 5 个覆盖精确主机名、一级通配、过期与未生效、受信根终止，以及两批独立校验与单独校验一致。该文件不可修改。
