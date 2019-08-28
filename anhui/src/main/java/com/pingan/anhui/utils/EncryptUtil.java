package com.pingan.anhui.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EncryptUtil {
	private static Logger logger =LoggerFactory.getLogger(RSAUtil.class);
	public static String signMsg(String xml,String charset) throws Exception {
		String infoSign = MD5Util.encryptMD5(Base64.str2Bytes(xml, charset));
		logger.debug("签名结果：{}",infoSign);
		return infoSign;
	}

	public static  boolean verifySign(String infoContent,String infoSign,String charset){
		try {
			String innerMd5 = MD5Util.encryptMD5(Base64.str2Bytes(infoContent, charset));
			return innerMd5.equals(infoSign);
		} catch (Exception e) {
			logger.error("验签异常！", e);
		}
		return false;
	}
	
	public static  String encryptByRSA(String infoContent ,RSAUtil rsa,String charset ) throws Exception {
		String ecnryptData = rsa.encryptByRSA(infoContent, charset);
		logger.debug("加密结果：{}",ecnryptData);
		return ecnryptData;
	}
//
	public static  String decryptByRSA(String infoContent ,RSAUtil rsa,String charset) throws Exception {
		String InfoContext = rsa.decryptByRSA(infoContent, charset);
		logger.debug("解密结果：{}",InfoContext);
		return InfoContext;
	}

}
