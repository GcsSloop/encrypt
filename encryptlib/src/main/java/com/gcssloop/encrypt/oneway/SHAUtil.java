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
 * Last modified 2017-09-07 17:29:28
 *
 * GitHub: https://github.com/GcsSloop
 * WeiBo: http://weibo.com/GcsSloop
 * WebSite: http://www.gcssloop.com
 */

package com.gcssloop.encrypt.oneway;

import android.support.annotation.Nullable;
import android.support.annotation.StringDef;

import com.gcssloop.encrypt.base.TextUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * SHA 工具类
 */
public class SHAUtil {

    public final static String SHA224 = "sha-224";
    public final static String SHA256 = "sha-256";
    public final static String SHA384 = "sha-384";
    public final static String SHA512 = "sha-512";

    @StringDef({SHA224, SHA256, SHA384, SHA512})
    @interface SHAType {}

    /**
     * Sha加密
     *
     * @param string 加密字符串
     * @param type   加密类型 ：{@link #SHA224}，{@link #SHA256}，{@link #SHA384}，{@link #SHA512}
     * @return SHA加密结果字符串
     */
    public static String sha(String string, @Nullable @SHAType String type) {
        if (TextUtils.isEmpty(string)) return "";
        if (TextUtils.isEmpty(type)) type = SHA256;

        try {
            MessageDigest md5 = MessageDigest.getInstance(type);
            byte[] bytes = md5.digest((string).getBytes());
            String result = "";
            for (byte b : bytes) {
                String temp = Integer.toHexString(b & 0xff);
                if (temp.length() == 1) {
                    temp = "0" + temp;
                }
                result += temp;
            }
            return result;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return "";
    }
}
