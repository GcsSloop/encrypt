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
 * Last modified 2017-09-07 17:29:17
 *
 * GitHub: https://github.com/GcsSloop
 * WeiBo: http://weibo.com/GcsSloop
 * WebSite: http://www.gcssloop.com
 */

package com.gcssloop.encrypt.oneway;

import android.support.annotation.NonNull;

import com.gcssloop.encrypt.base.CloseUtils;
import com.gcssloop.encrypt.base.TextUtils;

import java.io.File;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * MD5 工具类
 */
public class MD5Util {

    /**
     * MD5加密
     *
     * @param string 加密字符串
     * @return 加密结果字符串
     * @see #md5(String, String)
     */
    public static String md5(@NonNull String string) {
        return TextUtils.isEmpty(string) ? "" : md5(string, "");
    }

    /**
     * MD5加密(加盐)
     *
     * @param string 加密字符串
     * @param slat   加密盐值key
     * @return 加密结果字符串
     */
    public static String md5(@NonNull String string, String slat) {
        if (TextUtils.isEmpty(string)) return "";

        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            byte[] bytes = md5.digest((string + slat).getBytes());
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


    /**
     * MD5加密(多次)
     *
     * @param string 加密字符串
     * @param times  重复加密次数
     * @return 加密结果字符串
     */
    public static String md5(@NonNull String string, int times) {
        if (TextUtils.isEmpty(string)) return "";

        String md5 = string;
        for (int i = 0; i < times; i++) md5 = md5(md5);
        return md5;
    }


    /**
     * MD5加密(文件)
     * 可用于文件校验。
     *
     * @param file 加密文件
     * @return md5 数值
     */
    public static String md5(@NonNull File file) {
        if (!file.isFile()) {
            return "";
        }
        MessageDigest digest = null;
        FileInputStream in = null;
        byte buffer[] = new byte[1024];
        int len;
        try {
            digest = MessageDigest.getInstance("MD5");
            in = new FileInputStream(file);
            while ((len = in.read(buffer, 0, 1024)) != -1) {
                digest.update(buffer, 0, len);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }finally {
            CloseUtils.close(in);
        }
        BigInteger bigInt = new BigInteger(1, digest.digest());
        return bigInt.toString(16);
    }
}
