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
 * Last modified 2017-09-07 17:30:16
 *
 * GitHub: https://github.com/GcsSloop
 * WeiBo: http://weibo.com/GcsSloop
 * WebSite: http://www.gcssloop.com
 */

package com.gcssloop.encrypt.symmetric;

import android.annotation.SuppressLint;
import android.support.annotation.IntDef;

import com.gcssloop.encrypt.base.CryptoProvider;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static com.gcssloop.encrypt.base.BaseUtils.parseByte2HexStr;
import static com.gcssloop.encrypt.base.BaseUtils.parseHexStr2Byte;

/**
 * AES 工具类
 */
public class AESUtil {
    private final static String SHA1PRNG = "SHA1PRNG";

    @IntDef({Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE})
    @interface AESType {}

    /**
     * Aes加密/解密
     *
     * @param content  字符串
     * @param password 密钥
     * @param type     加密：{@link Cipher#ENCRYPT_MODE}，解密：{@link Cipher#DECRYPT_MODE}
     * @return 加密/解密结果字符串
     */
    public static String aes(String content, String password, @AESType int type) {
        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES");

            SecureRandom secureRandom;
            if (android.os.Build.VERSION.SDK_INT >= 24) {
                secureRandom = SecureRandom.getInstance(SHA1PRNG, new CryptoProvider());
            } else if (android.os.Build.VERSION.SDK_INT >= 17) {
                secureRandom = SecureRandom.getInstance(SHA1PRNG, "Crypto");
            } else {
                secureRandom = SecureRandom.getInstance(SHA1PRNG);
            }
            secureRandom.setSeed(password.getBytes());
            generator.init(128, secureRandom);
            SecretKey secretKey = generator.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
            @SuppressLint("GetInstance") Cipher cipher = Cipher.getInstance("AES");
            cipher.init(type, key);

            if (type == Cipher.ENCRYPT_MODE) {
                byte[] byteContent = content.getBytes("utf-8");
                return parseByte2HexStr(cipher.doFinal(byteContent));
            } else {
                byte[] byteContent = parseHexStr2Byte(content);
                return new String(cipher.doFinal(byteContent));
            }
        } catch (NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException |
                UnsupportedEncodingException | InvalidKeyException | NoSuchPaddingException |
                NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }
}
