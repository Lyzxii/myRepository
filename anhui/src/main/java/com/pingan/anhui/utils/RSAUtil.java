package com.pingan.anhui.utils;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;

import javax.crypto.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;


public class RSAUtil {
    private static Logger log = LoggerFactory.getLogger(RSAUtil.class);

    private PublicKey            publicKey;                                       // 对方公钥
    private PrivateKey           privateKey;                                      // 己方私钥

    private BouncyCastleProvider provider  = new BouncyCastleProvider();

    /**
     * RSA最大加密明文大小
     */
    //	private static final int MAX_ENCRYPT_BLOCK = 117;

    /**
     * RSA最大解密密文大小
     */
    private static final int     MAX_DECRYPT_BLOCK   = 128;

    /**
     * 签名算法
     */
    private static final String  SIGNATURE_ALGORITHM = "SHA256withRSA";           //SHA1withRSA MD5withRSA

    /**
     * 根据公私钥字符串构造加解密对象
     * 
     * @param publicKeyStr
     * @param privateKeyStr
     */
    public RSAUtil(String publicKeyStr, String privateKeyStr) {
        if (StringUtils.isNotBlank(publicKeyStr)) {
            this.publicKey = string2PublicKey(publicKeyStr);
        }
        if (StringUtils.isNotBlank(privateKeyStr)) {
            this.privateKey = string2PrivateKey(privateKeyStr);
        }
    }

    /**
     * 根据公钥证书路径及私钥证书路径和私钥证书密码构造加密解密对象
     * 
     * @param publicKeyPath 公钥证书路径
     * @param privateKeyPath 私钥证书路径
     * @param privateKeyPwd 私钥证书密码
     */
    public RSAUtil(String publicKeyPath, String privateKeyPath, String privateKeyPwd) {
        try {
            if (StringUtils.isNotBlank(publicKeyPath)) {
                this.publicKey = getPublicKeyFromX509(publicKeyPath);
            }
            if (StringUtils.isNotBlank(privateKeyPath)) {
                this.privateKey = getPrivateKey(privateKeyPath, privateKeyPwd);
            }
        } catch (Exception e) {
            log.error("RSA init exception:{}", e.getMessage(), e);
            throw new RuntimeException(String.format("RSA init exception:[%s]", e.getMessage()), e);
        }
    }

    /**
     * RSA公钥加密
     *
     * @param rawData
     * @param charset
     * @return
     */
    public String encryptByRSA(String rawData, String charset) {
        try {
            Cipher encodeCipher = Cipher.getInstance(publicKey.getAlgorithm(), provider);
            encodeCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            int blockSize = encodeCipher.getBlockSize();// 127
            byte[] data = rawData.getBytes(charset);
            int data_length = data.length;// 明文数据大小
            int outputSize = encodeCipher.getOutputSize(data_length);// 输出缓冲区大小
            // 计算出块的数量
            int blocksSize = (data_length + blockSize - 1) / blockSize;
            byte[] raw = new byte[outputSize * blocksSize];
            int i = 0;
            while (data_length - i * blockSize > 0) {
                if (data_length - i * blockSize > blockSize) {
                    encodeCipher.doFinal(data, i * blockSize, blockSize, raw, i * outputSize);
                } else {
                    encodeCipher.doFinal(data, i * blockSize, data_length - i * blockSize, raw, i * outputSize);
                }
                i++;
            }
            return Base64.encode(raw);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | UnsupportedEncodingException
                | ShortBufferException | IllegalBlockSizeException | BadPaddingException e) {
            log.error("RSA.encryptByRSA 公钥对数据{}使用字符集{}加密失败", rawData, charset, e);
            throw new RuntimeException(String.format("公钥对数据[%s]使用字符集[%s]加密失败", rawData, charset), e);
        }
    }

    /**
     * 功能:私钥RSA解密 作者: 澈力格尔很  创建日期:2019-7-16
     * 
     * @param encodeData
     * @param charset
     * @return
     */
    public String decryptByRSA(String encodeData, String charset) {
        try (ByteArrayOutputStream bout = new ByteArrayOutputStream(MAX_DECRYPT_BLOCK)) {
            Cipher decodeCipher = Cipher.getInstance(privateKey.getAlgorithm(), provider);
            decodeCipher.init(Cipher.DECRYPT_MODE, privateKey);
            int blockSize = decodeCipher.getBlockSize();
            int j = 0;
            byte[] raw = Base64.decode(encodeData);
            while (raw.length - j * blockSize > 0) {
                bout.write(decodeCipher.doFinal(raw, j * blockSize, blockSize));
                j++;
            }
            byte[] decryptedData = bout.toByteArray();
            return new String(decryptedData, charset);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
                | BadPaddingException | IOException e) {
            log.error("RSA.decryptByRSA 私钥对数据{}使用字符集{}加密失败", encodeData, charset, e);
            throw new RuntimeException(String.format("私钥对数据[%s]使用字符集[%s]解密失败", encodeData, charset), e);
        }
    }

    /**
     * 使用私钥签名
     * 
     * @param rawData
     * @param charset
     * @return
     */
    public String sign(String rawData, String charset) {
        try {
            Signature signSignature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signSignature.initSign(privateKey);
            signSignature.update(rawData.getBytes(charset));
            return Base64.encode(signSignature.sign());
        } catch (Exception e) {
            log.error("RSA.sign 使用私钥对数据{}进行{}签名失败", rawData, charset, e);
            throw new RuntimeException(String.format("使用私钥对数据[%s]进行[%s]签名失败", rawData, charset), e);
        }
    }

    /**
     * 功能:公钥验签
     * 
     * @param rawData
     * @param sign
     * @param charset
     * @return
     */
    public boolean verify(String rawData, String sign, String charset) {
        try {
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initVerify(publicKey);
            signature.update(rawData.getBytes(charset));
            return signature.verify(Base64.decode(sign));
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | UnsupportedEncodingException e) {
            log.error("RSA.verify 公钥使用签名串{}对数据{}进行{}验签失败", sign, rawData, charset, e);
            throw new RuntimeException(String.format("公钥使用签名串[%s]对数据[%s]进行[%s]验签失败", sign, rawData, charset), e);
        }
    }

    /**
     *密钥转成字符串
     * 
     * @param key
     * @return
     */
    public String keyToString(Key key) {
        try {
            return Base64.encode(key.getEncoded());
        } catch (Exception e) {
            log.error("RSA.keyToString 输出密钥{}字符串失败", key.getFormat(), e);
            throw new RuntimeException(String.format("输出密钥[%s]字符串失败", key.getFormat()), e);
        }
    }

    /**
     * 功能:公钥字符串转公钥
     * 
     * @param publicKeyStr
     * @return
     */
    public  PublicKey string2PublicKey(String publicKeyStr) {
        PublicKey publicKey = null;
        X509EncodedKeySpec bobPubKeySpec = null;
        try {
            bobPubKeySpec = new X509EncodedKeySpec(Base64.decode(publicKeyStr));
            // RSA对称加密算法
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            // 取公钥匙对象
            publicKey = keyFactory.generatePublic(bobPubKeySpec);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            log.error("RSA.string2PublicKey 公钥{}加载失败", publicKeyStr, e);
            throw new RuntimeException(String.format("公钥[%s]加载失败", publicKeyStr), e);
        }
        return publicKey;
    }

    /**
     * 功能: 私钥字符串转私钥
     * 
     * @param privateKyeStr
     * @return
     */
    public PrivateKey string2PrivateKey(String privateKyeStr) {
        PrivateKey privateKey = null;
        PKCS8EncodedKeySpec priPKCS8 = null;
        try {
            priPKCS8 = new PKCS8EncodedKeySpec(Base64.decode(privateKyeStr));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(priPKCS8);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            log.error("RSA.string2PrivateKey 私钥{}加载失败", privateKyeStr, e);
            throw new RuntimeException(String.format("私钥[%s]加载失败", privateKyeStr), e);
        }
        return privateKey;
    }

    /**
     * 功能: 根据路径加载公钥
     * 
     * @param publicKeyPath
     * @return
     */
    private PublicKey getPublicKeyFromX509(String publicKeyPath) {
        try (InputStream fin = getInputStream(publicKeyPath)) {
            CertificateFactory f = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) f.generateCertificate(fin);
            return certificate.getPublicKey();
        } catch (IOException | CertificateException e) {
            log.error("RSA.getPublicKeyFromX509 加载公钥证书路径{}失败", publicKeyPath, e);
            throw new RuntimeException(String.format("加载公钥证书路径[%s]失败", publicKeyPath), e);
        }
    }

    private InputStream getInputStream(String keyFilePath) {
        try {
            return new ClassPathResource(keyFilePath).getInputStream();
        } catch (IOException e) {
            log.error("RSA.getInputStream 文件{}加载失败", keyFilePath, e);
            throw new RuntimeException(String.format("文件[%s]加载失败", keyFilePath), e);
        }
    }

    /**
     * 功能: 加载私钥证书
     * 
     * @param privateKeyPath
     * @param password
     * @return
     */
    private PrivateKey getPrivateKey(String privateKeyPath, String password) {
        try (InputStream is = getInputStream(privateKeyPath)) {
            KeyStore store = KeyStore.getInstance("pkcs12");
            char[] passwordChars = password.toCharArray();
            store.load(is, passwordChars);
            Enumeration<String> e = store.aliases();
            if (e.hasMoreElements()) {
                String alias = e.nextElement();
                return (PrivateKey) store.getKey(alias, passwordChars);
            }
            throw new RuntimeException(String.format("无法加载私钥证书路径[%s]及密码[%s],请核对证书文件及密码", privateKeyPath, password));
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException
                | UnrecoverableKeyException e) {
            log.error("RSA.getInputStream 加载私钥证书路径{}及密码{}失败", privateKeyPath, password, e);
            throw new RuntimeException(String.format("加载私钥证书路径[%s]及密码[%s]失败", privateKeyPath, password), e);
        }
    }
}


