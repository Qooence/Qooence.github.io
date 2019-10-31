---
title: AES前后端加密解密
date: 2019-10-31 09:19:51
tags: 
- java
- 信息安全
categories:
- 信息安全
---

## AES前后端加密解密

在前后端分离项目中,为保证信息安全,对请求参数进行AES加密处理。后端使用AES-128-CBC加密模式。前端使用crypto-js进行AES加密,遇到加密结果不一致，后端无法解密问题。通过查阅资料,找到了解决方法：

> 前端不能直接使用后端的key及偏移量,需进行处理,详细处理请查询下面的代码。

### JAVA后端

```java
public class AES {
    /*
     * 加密用的Key 可以用26个字母和数字组成 此处使用AES-128-CBC加密模式，key需要为16位。
     */
    private static final String sKey = "0123456789ABCDEF";// 16位 key，可自行修改
    private static final String ivParameter = "FEDCBA9876543210";//16位 偏移量,可自行修改
    private static AES instance = null;

    private AES() {}

    public static AES getInstance() {
        if (instance == null)
            instance = new AES();
        return instance;
    }

    /**
     *  加密
     * @param content - 需加密的字符串
     * @return
     * @throws Exception
     */
    public static String encrypt(String content) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] raw = sKey.getBytes();
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        IvParameterSpec iv = new IvParameterSpec(ivParameter.getBytes());// 使用CBC模式，需要一个向量iv，可增加加密算法的强度
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        byte[] encrypted = cipher.doFinal(content.getBytes("utf-8"));
        return parseByte2HexStr(encrypted);
    }

    /**
     *  解密
     * @param srcStr - 密文
     * @return
     * @throws Exception
     */
    public static String decrypt(String srcStr) throws Exception {
        try {
            byte[] raw = sKey.getBytes("ASCII");
            SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec iv = new IvParameterSpec(ivParameter.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            byte[] encrypted = parseHexStr2Byte(srcStr);
            byte[] original = cipher.doFinal(encrypted);
            String originalString = new String(original, "utf-8");
            return originalString;
        } catch (Exception ex) {
            return null;
        }
    }

    /**2进制转化成16进制
     * @param buf
     * @return
     */
    public static String parseByte2HexStr(byte buf[]) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < buf.length; i++) {
            String hex = Integer.toHexString(buf[i] & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            sb.append(hex.toUpperCase());
        }
        return sb.toString();
    }

    /**将16进制转换为二进制
     * @param hexStr
     * @return
     */
    public static byte[] parseHexStr2Byte(String hexStr) {
        if (hexStr.length() < 1)
            return null;
        byte[] result = new byte[hexStr.length()/2];
        for (int i = 0;i< hexStr.length()/2; i++) {
            int high = Integer.parseInt(hexStr.substring(i*2, i*2+1), 16);
            int low = Integer.parseInt(hexStr.substring(i*2+1, i*2+2), 16);
            result[i] = (byte) (high * 16 + low);
        }
        return result;
    }

    public static void main(String[] args) throws Exception {
        // 需要加密的字串
        String cSrc = "{\"msg\":\"qwer一套带走\"}";
        // 加密
        long lStart = System.currentTimeMillis();
        String enString = AES.encrypt(cSrc);
        String fKey = parseByte2HexStr(sKey.getBytes());
        String fiv = parseByte2HexStr(ivParameter.getBytes());
        System.out.println("前端Key：" +fKey);
        System.out.println("前端偏移量：" + fiv);
        System.out.println("还原前端Key：" + new String(parseHexStr2Byte(fKey)));
        System.out.println("还原前端偏移量：" + new String(parseHexStr2Byte(fiv)));
        System.out.println("加密后的字串是：" + enString);
        long lUseTime = System.currentTimeMillis() - lStart;
        System.out.println("加密耗时：" + lUseTime + "毫秒");
        System.out.println("===========================================");

        // 解密
        lStart = System.currentTimeMillis();
        String DeString = AES.decrypt(enString);
        System.out.println("解密后的字串是：" + DeString);
        lUseTime = System.currentTimeMillis() - lStart;
        System.out.println("解密耗时：" + lUseTime + "毫秒");
    }
}
```

![后端加密解密结果](https://img-blog.csdnimg.cn/2019103023491389.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L2p5cTJraA==,size_16,color_FFFFFF,t_70)

### 前端

```javascript
import CryptoJS from "crypto-js";

var key = "30313233343536373839414243444546"; //密钥
var iv = "46454443424139383736353433323130"; //偏移量

export const getAES = function(data) {
    if (data === null) return null;
    let encrypted = CryptoJS.AES.encrypt(
        data,
        CryptoJS.enc.Hex.parse(key),
        {
            iv: CryptoJS.enc.Hex.parse(iv),
            mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
        }
    );
    let enced = encrypted.ciphertext.toString()
    return enced.toUpperCase();
}

export const getDAES = function(data) {
    if (data === null || data === undefined) return null;
    let encrypted = CryptoJS.AES.decrypt(
        CryptoJS.format.Hex.parse(data),
        CryptoJS.enc.Hex.parse(key),
        {
            iv: CryptoJS.enc.Hex.parse(iv),
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        }
    );
    return CryptoJS.enc.Utf8.stringify(encrypted);
}
```

```javascript
import {getAES,getDAES} from './util/aes'
export default {
  created(){
    let data = getAES("{\"msg\":\"qwer一套带走\"}");
    console.log(data);
    console.log(getDAES(data));
  }
}
```

![前端加密解密结果](https://img-blog.csdnimg.cn/20191030235710942.png)