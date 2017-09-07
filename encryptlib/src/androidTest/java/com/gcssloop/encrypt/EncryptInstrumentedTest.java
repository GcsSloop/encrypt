/*
 * Copyright 2017 GcsSloop
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Last modified 2017-09-07 10:44:09
 *
 * GitHub: https://github.com/GcsSloop
 * WeiBo: http://weibo.com/GcsSloop
 * WebSite: http://www.gcssloop.com
 */

package com.gcssloop.encrypt;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import com.gcssloop.encrypt.unsymmetric.RSAUtil;
import com.gcssloop.encrypt.encode.Base64Util;
import com.gcssloop.encrypt.oneway.MD5Util;
import com.gcssloop.encrypt.oneway.SHAUtil;
import com.gcssloop.encrypt.symmetric.AESUtil;
import com.gcssloop.encrypt.symmetric.DESUtil;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Map;

import javax.crypto.Cipher;

import static org.junit.Assert.assertEquals;

/**
 * Instrumentation test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class EncryptInstrumentedTest {
    @Test
    public void useAppContext() throws Exception {
        // Context of the app under test.
        Context appContext = InstrumentationRegistry.getTargetContext();

        assertEquals("com.gcssloop.encrypt.test", appContext.getPackageName());
    }

    /**
     * md5 工具单元测试
     *
     * @throws Exception
     */
    @Test
    public void md5_test() throws Exception {
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
        /*
        File file = new File("/Users/GcsSloop/Documents/档案库/1Cloud/TV小组/源码备份/Encrypt/Test/demo" +
                                     ".flv");
        assertEquals("a4e592e6160e0102e7ecc4ab6117b700", MD5Utils.md5(file));
        */
    }

    /**
     * base64 工具单元测试
     *
     * @throws Exception
     */
    @Test
    public void base64_test() throws Exception {
        System.out.println("base64");
        // base64 字符串加密解密测试
        assertEquals("R2NzU2xvb3DkuK3mloc=\n", Base64Util.base64EncodeStr("GcsSloop中文"));
        assertEquals("GcsSloop中文", Base64Util.base64DecodedStr("R2NzU2xvb3DkuK3mloc=\n"));
    }

    /**
     * aes 工具单元测试
     *
     * @throws Exception
     */
    @Test
    public void aes_test() throws Exception {
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
    }

    /**
     * des 工具单元测试
     *
     * @throws Exception
     */
    @Test
    public void des_test() throws Exception {
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
    }

    /**
     * sha 工具单元测试
     *
     * @throws Exception
     */
    @Test
    public void sha_test() throws Exception {
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
    }

    /**
     * rsa 工具单元测试
     *
     * @throws Exception
     */
    @Test
    public void rsa_test() throws Exception {
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
    }
}
