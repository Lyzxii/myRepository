package com.pingan.anhui.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.geerong.fincloud.crius.SLController.common.*;
import com.geerong.fincloud.crius.SLController.rest.BaseResultRequest;
import com.geerong.fincloud.crius.SLController.rest.PushResultResponse;
import com.geerong.fincloud.crius.client.common.shilong.*;
import com.geerong.fincloud.crius.openSDKController.util.JsonUtils;
import com.geerong.fincloud.crius.sdk.config.SlConfigure;
import com.geerong.fincloud.crius.slService.BaseSLService;
import com.geerong.fincloud.crius.utils.SpringContextUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static com.geerong.fincloud.crius.SLController.common.SlConstants.*;

/**
 * Created with IntelliJ IDEA
 * Created By wzj
 * Date: 2019/7/30
 * Time: 12:31
 * Description:
 * Modified By:
 */
@Slf4j
@Service
public class SLBuilder {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public Request buildRequest(EarlyRepaymentTrialRequest trialRequest) throws Exception {
        if (!StringUtils.hasText(trialRequest.getQudLay())) {
            trialRequest.setQudLay(SlConfigure.getQuadLay());
        }
        if (!StringUtils.hasText(trialRequest.getTrialFlag())) {
            trialRequest.setTrialFlag(TRIAL_FLAG);
        }
        if (!StringUtils.hasText(trialRequest.getTrialType())) {
            trialRequest.setTrialType(TRIAL_TYPE);
        }
        final Request request = new Request();
        request.setRequestSeqNo(buildRequestNo(SlConfigure.getCorporateCode()));
        request.setCorporateCode(SlConfigure.getCorporateCode());
        request.setInterfaceId(PREPAY_TRIAL);
        request.setProductType(SlConfigure.getProductType());
        final String requestJson = objectMapper.writeValueAsString(trialRequest);
        log.info("call shilong request param : requestJson= {}", requestJson);
        final String infoContent = EncryptUtil.encryptByRSA(requestJson, buildRsaUtil(), CHARSET);
        final String infoSign = EncryptUtil.signMsg(requestJson, CHARSET);
        log.info("sign result : {}", infoSign);
        request.setInfoContent(infoContent);
        request.setInfoSign(infoSign);
        request.setBankCode(SlConfigure.getBankCode());
        return request;
    }

    public Request buildRequest(ImgUploadResultRequest imgRequest) throws Exception {
        final Request request = new Request();
        if (!StringUtils.hasText(imgRequest.getQudLay())) {
            imgRequest.setQudLay(SlConfigure.getQuadLay());
        }
        if (!StringUtils.hasText(imgRequest.getApplNo())) {
            imgRequest.setApplNo(UUID.randomUUID().toString().replace("-", ""));
        }
        request.setRequestSeqNo(buildRequestNo(SlConfigure.getCorporateCode()));
        request.setCorporateCode(SlConfigure.getCorporateCode());
        request.setInterfaceId(PDF_QUERY);
        request.setProductType(SlConfigure.getProductType());
        final String requestJson = objectMapper.writeValueAsString(imgRequest);
        log.info("call shilong request param : requestJson= {}", requestJson);
        final String infoContent = EncryptUtil.encryptByRSA(requestJson, buildRsaUtil(), CHARSET);
        final String infoSign = EncryptUtil.signMsg(requestJson, CHARSET);
        log.info("sign result : {}", infoSign);
        request.setInfoContent(infoContent);
        request.setInfoSign(infoSign);
        request.setBankCode(SlConfigure.getBankCode());
        return request;
    }

    public EarlyRepaymentTrialResponse parseResponse(Response response) throws Exception {
        final EarlyRepaymentTrialResponse trialResponse = new EarlyRepaymentTrialResponse();
        if (SUCCESS_CODE.equals(response.getRespCode())) {
            final String infoContent = response.getInfoContent();
            final String infoSign = response.getInfoSign();
            final String decrypt = EncryptUtil.decryptByRSA(infoContent, buildRsaUtil(), CHARSET);
            if (!EncryptUtil.verifySign(decrypt,infoSign,CHARSET)) {
                log.error("Valid sign : {} failure : {}", infoSign, decrypt);
                return trialResponse;
            }
            final EarlyRepayment earlyRepayment = objectMapper.readValue(decrypt, EarlyRepayment.class);
            if (SUCCESS_CODE.equals(earlyRepayment.getRetCode())) {
                trialResponse.setEarlyRepayment(earlyRepayment);
                trialResponse.setErrorCode(earlyRepayment.getRetCode());
                trialResponse.setErrorMsg(earlyRepayment.getRetMsg());
            }else if (FAILURE_CODE.equals(earlyRepayment.getRetCode())) {
                trialResponse.setErrorCode(earlyRepayment.getRetCode());
                trialResponse.setErrorMsg(earlyRepayment.getRetMsg());
            }
        }else {
            trialResponse.setErrorCode(response.getRespCode());
            trialResponse.setErrorMsg(response.getRespMsg());
        }
        return trialResponse;
    }

    public ImgUploadResultResponse parseImgResponse(Response response) throws Exception {
        final ImgUploadResultResponse imgResponse = new ImgUploadResultResponse();
        if (SUCCESS_CODE.equals(response.getRespCode())) {
            final String infoContent = response.getInfoContent();
            final String infoSign = response.getInfoSign();
            final String decrypt = EncryptUtil.decryptByRSA(infoContent, buildRsaUtil(), CHARSET);
            if (!EncryptUtil.verifySign(decrypt,infoSign,CHARSET)) {
                log.error("Valid sign : {} failure : {}", infoSign, decrypt);
                return imgResponse;
            }
            final UploadResult result = objectMapper.readValue(decrypt, UploadResult.class);
            imgResponse.setErrorCode(result.getRetCode());
            imgResponse.setErrorMsg(result.getRetMsg());
            imgResponse.setUploadResult(result);
        }else {
            imgResponse.setErrorCode(response.getRespCode());
            imgResponse.setErrorMsg(response.getRespMsg());
        }
        return imgResponse;
    }

    private String buildRequestNo(String corporateCode) {
        return corporateCode
                + new SimpleDateFormat(TIME_FORMAT).format(new Date())
                + (int)((Math.random()*9+1)*10);//100000测试需要先改成10
    }

    private RSAUtil buildRsaUtil() {
        return new RSAUtil(SlConfigure.getPublicKeyPath(),SlConfigure.getPrivateKeyPath(),SlConfigure.getPrivateKeyPwd());
    }

    public void exchange(Request request, Response response) {
        BeanUtils.copyProperties(request,response);
        final String infoContent = request.getInfoContent();
        final String infoSign = request.getInfoSign();
        final RSAUtil rsaUtil = buildRsaUtil();
        String decryptByRSA = null;
        try {
            decryptByRSA = EncryptUtil.decryptByRSA(infoContent, rsaUtil, CHARSET);
        } catch (Exception e) {
            log.error("decrypt request infoContent failure: {}", infoContent, e);
            response.fillRet(RetCode.DECRYPT);
            return;
        }
        if (!EncryptUtil.verifySign(decryptByRSA, infoSign, CHARSET)) {
            response.fillRet(RetCode.CHECK_SIGN);
            return;
        }
        if(!LOAN_DETAIL.equals(request.getInterfaceId()) && !APPROVE_RESULT.equals(request.getInterfaceId())) {
            response.fillRet(RetCode.NOT_KNOWN);
            return;
        }
        final BaseSLService baseSLService = SpringContextUtil.getBean(request.getInterfaceId());
        final BaseResultRequest baseResultRequest = baseSLService.deSerialize(decryptByRSA);
        final PushResultResponse resultResponse = baseSLService.push(baseResultRequest,parseTenantConfig(request.getProductType(),request.getCorporateCode()));
        try {
            final String resultInfoContent = objectMapper.writeValueAsString(resultResponse);
            response.setInfoContent(EncryptUtil.encryptByRSA(resultInfoContent, rsaUtil, CHARSET));
            response.setInfoSign(EncryptUtil.signMsg(resultInfoContent,CHARSET));
            response.fillRet(RetCode.SUCCESS);
            return;
        } catch (Exception e) {
            log.error("Make [serialize or encrypt] response:{} failure", resultResponse, e);
            response.fillRet(RetCode.NOT_KNOWN);
            return;
        }
    }

    private TenantConfig parseTenantConfig(String productType, String corporateCode) {
        final String tenantConfigJson = SlConfigure.getTenantConfig();
        try {
            Assert.notNull(productType,"productType is required");
            Assert.notNull(corporateCode,"corporateCode is required");
            List<TenantConfig> tenantConfigList = JsonUtils.json2list(tenantConfigJson,TenantConfig.class);
            for (TenantConfig tenantConfig : tenantConfigList) {
                if (productType.equals(tenantConfig.getProductType()) && corporateCode.equals(tenantConfig.getCorporateCode())) {
                    return tenantConfig;
                }
            }
            log.error("Please check tenant config : {}", tenantConfigJson);
            return null;
        } catch (Exception e) {
            log.error("Parse tenant config : {} failure, please check it", tenantConfigJson, e);
            return null;
        }
    }

}
