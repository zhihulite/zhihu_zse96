# 知乎x-zse96参数生成工具

## 项目简介

本项目提供Python、Node.js、Lua和Dart四种语言的实现，用于生成知乎App中的x-zse96加密参数。

## 项目结构

```
├── python/                # Python 实现
├── nodejs/                # Node.js 实现 ( test.js 包含获取 zst82 zst81 生成游客凭证 请求知乎api示例)
├── lua/                   # Lua 实现
├── dart/                  # Dart 实现
├── test.crx               # 示例获取知乎登录数据的浏览器插件(0.1)
└── x-req-signature.py     # x-req-signature 参数生成（基于 libencrypt.so 中 encrypt 函数 的 Python 实现）
```

每个语言目录包含：
- `laes_utils.*` - 核心加密模块
- `main.*` - 示例调用文件

## 使用说明

1. 选择需要的语言版本
2. 运行对应目录下的示例文件
3. 查看生成的x-zse96参数

## 注意事项

- 仅供学习研究使用
- 请勿用于商业用途
- 知乎可能会更新加密算法

## 环境要求

- Python: 3.12+
- Node.js: 22+  
- Lua: 5.4+
- Dart: 3.6.1+

## 附注：如何找到知乎原始加密数据

### 一、从网络请求切入

get请求关键Header：

```
X-Zse-96: 1.0_xxxxxxxx
X-Zse-93: 101_1_1.0
```

其他类型请求例如 post请求关键Header为post请求体

### 二、核心类定位技巧

知乎 9.33.0 版本中，可通过 Hook com.zhihu.android.d3.h.r.b(java.lang.String) 获取原始加密数据，Hook com.zhihu.android.a2.a.b([B) 获取加密后的结果
当然 你也可以获取任意版本的加解密类 例如
寻找 com/bangcle/c 的调用处 一般调用处就是封装的解密/加密方法 一般知乎会封装多个接口 最常用的是 CryptoUtils.java 找到相关类 hook类全部方法 即可获得加解密
手动导航到 com.bangcle.c 类 看a方法和b方法调用的是decrypt还是enceypt即可获得a和b方法哪个是用来加解密的
搜索代码 CryptoUtils.java 即可获得具体类 知乎并未对打包后原始类名隐藏
搜索代码 SignInterceptor.java 找到相关类
注:

- `H.d("G51CEEF09BA7DF27F")` → "X-Zse-96"
- `H.d("G38CD8525")` → "1.0"
- `H.d("G51CEEF09BA7DF27A")` → "X-Zse-93"

8.1.4.0

```java
private Request e(Request request) throws IOException {
    StringBuilder sb = new StringBuilder();
    // a(Request request, StringBuilder sb) 处理request和zse96原始字符串合成
    Request a = a(request, sb);
    // String a(String str) md5加密
    String a2 = a(sb.toString().substring(0, sb.length() - 1));
    if (a2 == null) {
        return a;
    }
    return request.newBuilder().addHeader(H.d("G51CEEF09BA7DF27F"), H.d("G38CD8525") + new String(this.c.encode(this.b.encrypt(a2.toLowerCase().getBytes())))).addHeader(H.d("G51CEEF09BA7DF27A"), this.a).build();
}
```

9.33.0

```java
private Request k(final Request request) throws IOException {
    final PatchProxyResult proxy = PatchProxy.proxy(new Object[] {
        request
    }, (Object) this, r.changeQuickRedirect, false, 129054, new Class[0], (Class) Request.class);
    if (proxy.isSupported) {
        return (Request) proxy.result;
    }
    final StringBuilder sb = new StringBuilder();
    Request request2 = this.e(request, sb);
    final String b = b(sb.toString().substring(0, sb.length() - 1));
    if (b != null) {
        final byte[] a = this.b.a(b.toLowerCase().getBytes());
        final StringBuilder sb2 = new StringBuilder();
        sb2.append(H.d("G38CD8525"));
        sb2.append(new String(this.c.a(a)));
        request2 = request.newBuilder().addHeader(H.d("G51CEEF09BA7DF27F"), sb2.toString()).addHeader(H.d("G51CEEF09BA7DF27A"), this.a).build();
    }
    return request2;
}
```

更高版本例如10.x版本可能已去除字符串加密 所以直接搜索关键字  例如 X-Zse-96 即可
