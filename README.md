# Encrypt(加密工具)

字符串，byte[]，文件等对象的加密和解密工具集合，包含了多种加密方案。

| 加密类型  | 摘要                | 相关方法            |
| ----- | ----------------- | --------------- |
| 简单加密  | 换一种编码格式           | Base64Util      |
| 单向加密  | 只能加密，不能解密         | MD5Util、SHAUtil |
| 对称加密  | 使用相同的秘钥加密和解密      | AESUtil、DESUtil |
| 非对称加密 | 分公钥和私钥，一个加密，另一个解密 | RSAUtil         |

## 使用方法

### Base64util

| 方法                                  | 摘要   |
| ----------------------------------- | ---- |
| String  base64EncodeStr(String str) | 编码   |
| String base64DecodedStr(String str) | 解码   |

单元测试：

```java
System.out.println("base64");
// base64 字符串加密解密测试
assertEquals("R2NzU2xvb3DkuK3mloc=\n", Base64Util.base64EncodeStr("GcsSloop中文"));
assertEquals("GcsSloop中文", Base64Util.base64DecodedStr("R2NzU2xvb3DkuK3mloc=\n"));
```

### MD5Util

| 方法                                     | 摘要         |
| -------------------------------------- | ---------- |
| String md5(String string)              | 加密字符串      |
| String md5(String string, String slat) | 加密字符串同时加盐  |
| String md5(String string, int times)   | 多次加密       |
| String md5(File file)                  | 计算文件的md5数值 |


单元测试：
```java
System.out.println("md5");
// MD5 字符串加密测试
assertEquals("", MD5Util.md5(""));
assertEquals("386d3ff3fa6def1ec307428e885e03a1", MD5Util.md5("GcsSloop中文"));
assertEquals("fd01aa74bb73bbdb094bae28a558c6d1", MD5Util.md5("GcsSloop中文", "salt"));

// MD5 多次加密测试
assertEquals("GcsSloop中文", MD5Util.md5("GcsSloop中文", 0));
assertEquals("386d3ff3fa6def1ec307428e885e03a1", MD5Util.md5("GcsSloop中文", 1));
assertEquals("2d9fdd834c5c852fa2f946b670f3731f", MD5Util.md5("GcsSloop中文", 2));
assertEquals("211dd7a16d5a01df756278cea9a38d53", MD5Util.md5("GcsSloop中文", 3));

// MD5 文件md5测试
File file = new File("./Encrypt/Test/demo" +
                             ".flv");
assertEquals("a4e592e6160e0102e7ecc4ab6117b700", MD5Util.md5(file));
```

### SHAUtil

| 方法                                     | 摘要   |
| -------------------------------------- | ---- |
| String sha(String string, String type) | 加密   |

单元测试：

```java
System.out.println("sha");
// des 字符串加密解密测试
String source = "GcsSloop中文";
assertEquals("b9dd1d754ee3ac16dc584b8fd4655ca581a0637eab8ff25128b0a522372e7233",
             SHAUtil.sha(source, null));
assertEquals("34d44835ce4cc4d7ecf66428e49273bf02f748d7213be24c767c5f4f",
             SHAUtil.sha(source, SHAUtil.SHA224));
assertEquals("b9dd1d754ee3ac16dc584b8fd4655ca581a0637eab8ff25128b0a522372e7233",
             SHAUtil.sha(source, SHAUtil.SHA256));
assertEquals("2e3c27201c21b06b01289ebef09c9c36e752ca6a5b6425ca7b2501b4baaed29876954ca710b7e75c80b7b542df28fde6",
             SHAUtil.sha(source, SHAUtil.SHA384));
assertEquals("bc3f55fcb03272ee166d7804ccba348ffba05ddce08bf3fab719fa2c97c8dc71993fc9524e21b8fee9491aafc0b309ebca797163bca45ece7c3dd73dae3698ee",
             SHAUtil.sha(source, SHAUtil.SHA512));
```

### AESUtil

| 方法                                       | 摘要    |
| ---------------------------------------- | ----- |
| String aes(String content, String password,  int type) | 加密／解密 |

单元测试：

```java
System.out.println("aes");
// aes 字符串加密解密测试
String source = "GcsSloop中文";
String key = "1234567890123456";
System.out.println("原数据 = " + source);
String aesStr = AESUtil.aes(source, key, Cipher.ENCRYPT_MODE);
System.out.println("加密后 = " + aesStr);
String result = AESUtil.aes(aesStr, key, Cipher.DECRYPT_MODE);
System.out.println("解密后 = " + result);
assertEquals(source, result);
```

### DESUtil

| 方法                                       | 摘要    |
| ---------------------------------------- | ----- |
| String des(String content, String password,  int type) | 加密／解密 |

单元测试：

```java
System.out.println("des");
// des 字符串加密解密测试
String source = "GcsSloop中文";
String key = "1234567890123456";
System.out.println("原数据 = " + source);
String aesStr = DESUtil.des(source, key, Cipher.ENCRYPT_MODE);
System.out.println("加密后 = " + aesStr);
String result = DESUtil.des(aesStr, key, Cipher.DECRYPT_MODE);
System.out.println("解密后 = " + result);
assertEquals(source, result);
```

### RSAUtil

| 方法                                       | 摘要                             |
| ---------------------------------------- | ------------------------------ |
| Map\<String, Object\> getKeyPair()       | 随机获取密钥(公钥和私钥), 客户端公钥加密，服务器私钥解密 |
| String getKey(Map\<String, Object\> keyMap, boolean isPublicKey) | 获取公钥/私钥(true：获取公钥，false：获取私钥)  |
| String sign(byte[] data, String privateKey) | 获取数字签名                         |
| boolean verify(byte[] data, String publicKey, String sign) | 数字签名校验                         |
| byte[] rsa(byte[] data, String string,  int type) | Rsa加密/解密（一般情况下，公钥加密私钥解密）       |

单元测试：

```java
System.out.println("rsa");
// des 字符串加密解密测试
byte[] data = "GcsSloop中文".getBytes();

// 密钥与数字签名获取
Map<String, Object> keyMap = RSAUtil.getKeyPair();
String publicKey = RSAUtil.getKey(keyMap, true);
System.out.println("rsa获取公钥： " + publicKey);
String privateKey = RSAUtil.getKey(keyMap, false);
System.out.println("rsa获取私钥： " + privateKey);

// 公钥加密私钥解密
byte[] rsaPublic =
        RSAUtil.rsa(data, publicKey, RSAUtil.RSA_PUBLIC_ENCRYPT);
System.out.println("rsa公钥加密： " + new String(rsaPublic));
System.out.println("rsa私钥解密： " + new String(
        RSAUtil.rsa(rsaPublic, privateKey, RSAUtil.RSA_PRIVATE_DECRYPT)));

// 私钥加密公钥解密
byte[] rsaPrivate =
        RSAUtil.rsa(data, privateKey, RSAUtil.RSA_PRIVATE_ENCRYPT);
System.out.println("rsa私钥加密： " + new String(rsaPrivate));
System.out.println("rsa公钥解密： " + new String(
        RSAUtil.rsa(rsaPrivate, publicKey, RSAUtil.RSA_PUBLIC_DECRYPT)));

// 私钥签名及公钥签名校验
String signStr = RSAUtil.sign(rsaPrivate, privateKey);
System.out.println("rsa数字签名生成： " + signStr);
System.out.println("rsa数字签名校验： " + RSAUtil.verify(rsaPrivate, publicKey, signStr));
```



### 添加方法

1. 在你的项目根 `build.gradle` 中添加上远程仓库：

```groovy
allprojects {
    repositories {
        jcenter()
        // 就是下面这一行
        maven { url "http://lib.gcssloop.com/repository/gcssloop-central/" }
    }
}
```

2. 在需要引用的 module 添加具体依赖。

```groovy
compile 'com.gcssloop.util:encrypt:1.0.2'
```



### 版本信息

#### v1.0.2

尝试修复 RSAUtils 加密图片时问题。

#### v1.0.1

降低最低版本兼容性。

#### v1.0.0

添加基本的加密解密工具和辅助工具类。

- base
  - **Base64**
  - **BaseUtils**
  - **CloseUtils**
  - **CryptoProvider**
  - **TextUtils**
- encode
  - **Base64Util**
- oneway
  - **MD5Util**
  - **SHAUtil**
- symmetric
  - **AESUtil**
  - **DESUtil**
- unsymmetric
  - **RSAUtil**



## 备注

本工具库中大部分代码参考自 [一个聚合的加解密工具类](http://blog.csdn.net/gzejia/article/details/52755332) 但在测试过程中发现部分方法结果不正确，以及部分方法在Android升级过程中进行了修改，所以改进了一部分，特此制作一个工具库，如果发现有什么不准确的地方欢迎提交 Issues。



## 参考资料

[一个聚合的加解密工具类](http://blog.csdn.net/gzejia/article/details/52755332) 

[在线加密解密](http://tool.oschina.net/encrypt?type=2)

[Android数据加密之Aes加密](http://www.cnblogs.com/whoislcj/p/5473030.html)

[java.security.NoSuchProviderException: no such provider: Crypto](https://my.oschina.net/yaly/blog/856362)



## 作者简介

#### 作者微博: [@GcsSloop](http://weibo.com/GcsSloop)

#### 个人网站: http://www.gcssloop.com

<a href="http://www.gcssloop.com/info/about/" target="_blank"> <img src="http://ww4.sinaimg.cn/large/005Xtdi2gw1f1qn89ihu3j315o0dwwjc.jpg" width="300"/> </a>


## 版权信息

```
Copyright (c) 2017 GcsSloop

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
