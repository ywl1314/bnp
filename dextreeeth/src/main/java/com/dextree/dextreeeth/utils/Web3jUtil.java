package com.dextree.dextreeeth.utils;

import com.dextree.dextreeeth.bean.Constant;

import org.web3j.crypto.CipherException;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.WalletUtils;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.Web3jFactory;
import org.web3j.protocol.http.HttpService;

import java.io.IOException;

public class Web3jUtil {
    private static Web3jUtil web3jUtil;
    public  Web3j web3;
    Credentials credentials;

    private Web3jUtil() {


    }

    public static synchronized Web3jUtil getInstanceCredentials(String s, String a) {
        //初始化XMPPTCPConnection相关配置
        if (web3jUtil == null) {
            web3jUtil = new Web3jUtil();
            try {
                web3jUtil.credentials = WalletUtils.loadCredentials(s, a);
            } catch (IOException e) {
                e.printStackTrace();
            } catch (CipherException e) {
                e.printStackTrace();
            }
            return web3jUtil;
        } else {
            if (web3jUtil.credentials == null) {
                try {
                    web3jUtil.credentials = WalletUtils.loadCredentials(s, a);
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (CipherException e) {
                    e.printStackTrace();
                }
            }
            return web3jUtil;
        }

    }

    public static synchronized Web3jUtil getInstanceWeb3() {
        if (web3jUtil == null) {
            web3jUtil = new Web3jUtil();
            web3jUtil.web3 = Web3jFactory.build(new HttpService(Constant.MAInURL));
            return web3jUtil;
        } else {
            if (web3jUtil.web3 == null) {
                web3jUtil.web3 = Web3jFactory.build(new HttpService(Constant.MAInURL));
            }
            return web3jUtil;
        }
    }
}
