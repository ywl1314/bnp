package com.dextree.dextreeeth.utils;


import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.util.Log;


import com.dextree.dextreeeth.bean.Constant;
import com.dextree.dextreeeth.bean.ETHWallet;
import com.dextree.dextreeeth.listener.CallBack;
import com.dextree.organisation.Benepit.BenepitToken;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.wallet.DeterministicSeed;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.crypto.CipherException;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.crypto.Wallet;
import org.web3j.crypto.WalletFile;
import org.web3j.crypto.WalletUtils;
import org.web3j.protocol.ObjectMapperFactory;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.request.EthFilter;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.EthEstimateGas;
import org.web3j.protocol.core.methods.response.EthGasPrice;
import org.web3j.protocol.core.methods.response.EthGetBalance;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.tx.Contract;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;
import java.io.File;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import io.reactivex.Observable;
import io.reactivex.ObservableEmitter;
import io.reactivex.ObservableOnSubscribe;
import io.reactivex.Observer;
import io.reactivex.android.schedulers.AndroidSchedulers;
import io.reactivex.disposables.Disposable;
import io.reactivex.schedulers.Schedulers;
import rx.Subscriber;


public class ETHWalletUtils {

    private static final int COUNT = 10;  // don't set too high if using a real Ethereum network
    private static final long POLLING_FREQUENCY = 15000;
    private static ObjectMapper objectMapper = ObjectMapperFactory.getObjectMapper();
    /**
     * 随机
     */
    private static final SecureRandom secureRandom = SecureRandomUtils.secureRandom();
    private Credentials credentials;
    /**
     * 通用的以太坊基于bip44协议的助记词路径 （imtoken jaxx Metamask myetherwallet）
     */
    public static String ETH_JAXX_TYPE = "m/44'/60'/0'/0/0";
    public static String ETH_LEDGER_TYPE = "m/44'/60'/0'/0";
    public static String ETH_CUSTOM_TYPE = "m/44'/60'/1'/0/0";

    /**
     * 创建助记词，并通过助记词创建钱包
     *
     * @param walletName
     * @param pwd
     * @return
     */
    public static ETHWallet generateMnemonic(String walletName, String pwd) {
        String[] pathArray = ETH_JAXX_TYPE.split("/");
        String passphrase = "";
        long creationTimeSeconds = System.currentTimeMillis() / 1000;

        DeterministicSeed ds = new DeterministicSeed(secureRandom, 128, passphrase, creationTimeSeconds);
        return generateWalletByMnemonic(walletName, ds, pathArray, pwd);
    }


    /**
     * @param walletName 钱包名称
     * @param ds         助记词加密种子
     * @param pathArray  助记词标准
     * @param pwd        密码
     * @return
     */
    @Nullable
    public static ETHWallet generateWalletByMnemonic(String walletName, DeterministicSeed ds,
                                                     String[] pathArray, String pwd) {
        //种子
        byte[] seedBytes = ds.getSeedBytes();
//        System.out.println(Arrays.toString(seedBytes));
        //助记词
        List<String> mnemonic = ds.getMnemonicCode();
//        System.out.println(Arrays.toString(mnemonic.toArray()));
        if (seedBytes == null)
            return null;
        DeterministicKey dkKey = HDKeyDerivation.createMasterPrivateKey(seedBytes);
        for (int i = 1; i < pathArray.length; i++) {
            ChildNumber childNumber;
            if (pathArray[i].endsWith("'")) {
                int number = Integer.parseInt(pathArray[i].substring(0,
                        pathArray[i].length() - 1));
                childNumber = new ChildNumber(number, true);
            } else {
                int number = Integer.parseInt(pathArray[i]);
                childNumber = new ChildNumber(number, false);
            }
            dkKey = HDKeyDerivation.deriveChildKey(dkKey, childNumber);
        }
        ECKeyPair keyPair = ECKeyPair.create(dkKey.getPrivKeyBytes());
        ETHWallet ethWallet = generateWallet(walletName, pwd, keyPair);
        if (ethWallet != null) {
            ethWallet.setMnemonic(convertMnemonicList(mnemonic));
        }
        return ethWallet;
    }

    private static String convertMnemonicList(List<String> mnemonics) {
        StringBuilder sb = new StringBuilder();
        for (String mnemonic : mnemonics
                ) {
            sb.append(mnemonic);
            sb.append(" ");
        }
        return sb.toString();
    }

    @Nullable
    private static ETHWallet generateWallet(String walletName, String pwd, ECKeyPair ecKeyPair) {
        WalletFile walletFile;
        try {
            walletFile = Wallet.create(pwd, ecKeyPair, 1024, 1); // WalletUtils. .generateNewWalletFile();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

        BigInteger publicKey = ecKeyPair.getPublicKey();
        String s = publicKey.toString();
        LogUtils.i("ETHWalletUtils", "publicKey = " + s);
        String wallet_dir = AppFilePath.Wallet_DIR;
        LogUtils.i("ETHWalletUtils", "wallet_dir = " + wallet_dir);
        String keystorePath = "keystore_" + walletName + ".json";
        File destination = new File(wallet_dir, "keystore_" + walletName + ".json");

        //目录不存在则创建目录，创建不了则报错
        if (!createParentDir(destination)) {
            return null;
        }
        try {
            objectMapper.writeValue(destination, walletFile);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
        ETHWallet ethWallet = new ETHWallet();
        ethWallet.setName(walletName);
        ethWallet.setPublicKey(s);
        ethWallet.setAddress(Keys.toChecksumAddress(walletFile.getAddress()));
        ethWallet.setKeystorePath(destination.getAbsolutePath());
        ethWallet.setPassword(Md5Utils.md5(pwd));
        return ethWallet;
    }


    private static boolean createParentDir(File file) {
        //判断目标文件所在的目录是否存在
        if (!file.getParentFile().exists()) {
            //如果目标文件所在的目录不存在，则创建父目录
            System.out.println("目标文件所在目录不存在，准备创建");
            if (!file.getParentFile().mkdirs()) {
                System.out.println("创建目标文件所在目录失败！");
                return false;
            }
        }
        return true;
    }


    /**
     * 导出明文私钥
     *
     * @param pwd 钱包密码
     * @return
     */

    public static String derivePrivateKey(String pash, String pwd) {

        Credentials credentials;
        ECKeyPair keypair;
        String privateKey = null;
        try {
            credentials = WalletUtils.loadCredentials(pwd, pash);
            keypair = credentials.getEcKeyPair();
            privateKey = Numeric.toHexStringNoPrefixZeroPadded(keypair.getPrivateKey(), Keys.PRIVATE_KEY_LENGTH_IN_HEX);
        } catch (CipherException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return privateKey;
    }


    /**
     * 导出keystore文件
     *
     * @param pwd
     * @return
     */
    public static String deriveKeystore(String pass, String pwd) {
        String keystore = null;
        WalletFile walletFile;
        try {
            walletFile = objectMapper.readValue(new File(pass), WalletFile.class);
            keystore = objectMapper.writeValueAsString(walletFile);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return keystore;
    }


    /**
     * 删除单个文件
     *
     * @param fileName 要删除的文件的文件名
     * @return 单个文件删除成功返回true，否则返回false
     */
    public static boolean deleteFile(String fileName) {
        File file = new File(fileName);
        // 如果文件路径所对应的文件存在，并且是一个文件，则直接删除
        if (file.exists() && file.isFile()) {
            if (file.delete()) {
//                System.out.println("删除单个文件" + fileName + "成功！");
                return true;
            } else {
//                System.out.println("删除单个文件" + fileName + "失败！");
                return false;
            }
        } else {
//            System.out.println("删除单个文件失败：" + fileName + "不存在！");
            return false;
        }
    }

    @NonNull
    private static String generateNewWalletName() {
        char letter1 = (char) (int) (Math.random() * 26 + 97);
        char letter2 = (char) (int) (Math.random() * 26 + 97);
        String walletName = String.valueOf(letter1) + String.valueOf(letter2) + "-新钱包";
        return walletName;
    }

    /**
     * 通过明文私钥导入钱包
     *
     * @param privateKey
     * @param pwd
     * @return
     */
    public static void loadWalletByPrivateKey(final String privateKey, final String pwd, final CallBack callBack) {


        Observable.create(new ObservableOnSubscribe<ETHWallet>() {
            @Override
            public void subscribe(ObservableEmitter<ETHWallet> e) throws Exception {
                Credentials credentials = null;
                ECKeyPair ecKeyPair = ECKeyPair.create(Numeric.toBigInt(privateKey));
                ETHWallet ethWallet = generateWallet(generateNewWalletName(), pwd, ecKeyPair);
                e.onNext(ethWallet);
            }
        }).subscribeOn(Schedulers.io())
                .observeOn(AndroidSchedulers.mainThread())
                .subscribe(new Observer<ETHWallet>() {
                    @Override
                    public void onSubscribe(Disposable d) {
                        callBack.start();
                    }

                    @Override
                    public void onNext(ETHWallet wallet) {

                        callBack.end(wallet);
                    }

                    @Override
                    public void onError(Throwable e) {
                        callBack.error();
                    }

                    @Override
                    public void onComplete() {

                    }
                });
    }

    public static String getEstimateGas(String gas) {
        BigDecimal bigDecimal = Convert.fromWei("23192", Convert.Unit.GWEI);
        BigDecimal gas1 = new BigDecimal(gas);
        BigDecimal multiply = bigDecimal.multiply(gas1);
        return multiply.setScale(6, RoundingMode.HALF_UP).toString();
    }

    public static void getEstimateGas(final CallBack callBack, final String from, final String gas, final String to) {
        final BigInteger bigInteger = Convert.toWei(gas, Convert.Unit.GWEI).toBigInteger();


        Observable.create(new ObservableOnSubscribe<String>() {
            @Override
            public void subscribe(final ObservableEmitter<String> e) throws Exception {

                Request<?, EthGetTransactionCount> ethGetTransactionCountRequest = Web3jUtil.getInstanceWeb3().web3.ethGetTransactionCount(from, DefaultBlockParameterName.LATEST);
                EthGetTransactionCount send = ethGetTransactionCountRequest.send();
                String method = "transfer";
                List<Type> inputArgs = new ArrayList<>();
                inputArgs.add(new Address(to));
                inputArgs.add(new Uint256(BigDecimal.valueOf(Long.parseLong("1")).multiply(BigDecimal.TEN.pow(18)).toBigInteger()));
                List<TypeReference<?>> outputArgs = new ArrayList<>();
                String funcABI = FunctionEncoder.encode(new Function(method, inputArgs, outputArgs));
                BigInteger transactionCount = send.getTransactionCount();
                Request<?, EthEstimateGas> ethEstimateGasRequest = Web3jUtil.getInstanceWeb3().web3.ethEstimateGas(Transaction.createFunctionCallTransaction(
                        from, transactionCount, bigInteger, null, to, funcABI));
                Future<EthEstimateGas> ethEstimateGasFuture = ethEstimateGasRequest.sendAsync();
                EthEstimateGas ethEstimateGas = ethEstimateGasFuture.get();
                BigInteger amountUsed = ethEstimateGas.getAmountUsed();
                BigDecimal bigDecimal = Convert.fromWei(amountUsed.toString(), Convert.Unit.GWEI);
                e.onNext(bigDecimal.toString());
            }
        }).subscribeOn(Schedulers.io())
                .observeOn(AndroidSchedulers.mainThread())
                .subscribe(new Observer<String>() {
                    @Override
                    public void onSubscribe(Disposable d) {
                        callBack.start();
                    }

                    @Override
                    public void onNext(String gas) {

                        callBack.end(gas);
                    }

                    @Override
                    public void onError(Throwable e) {
                        callBack.error();
                    }

                    @Override
                    public void onComplete() {

                    }
                });

    }


    public static String getETHbalance(String address) {
        try {
            EthGetBalance ethGetBalance = Web3jUtil.getInstanceWeb3().web3.ethGetBalance(address, DefaultBlockParameterName.LATEST)
                    .sendAsync().get();
            BigDecimal bigDecimal = Convert.fromWei(ethGetBalance.getBalance().toString(), Convert.Unit.ETHER);
//        float etHbalance = ETHWalletUtils.getETHbalance("0xC6660680fc1eC27d99569BE57f1e66A46FE53903");
            int round = Math.round(bigDecimal.floatValue() * 1000);
            double v = round * 0.001;
            String result = String.format("%.8f", v);
            return result;
        } catch (ExecutionException e) {
            e.printStackTrace();
            return "";
        } catch (InterruptedException e) {
            e.printStackTrace();
            return "";
        }
    }

    public static void getGasPrice(final CallBack callBack) {


        Observable.create(new ObservableOnSubscribe<Integer>() {
            @Override
            public void subscribe(final ObservableEmitter<Integer> e) throws Exception {
                Request<?, EthGasPrice> ethGasPriceRequest = Web3jUtil.getInstanceWeb3().web3.ethGasPrice();
                ethGasPriceRequest.observable().subscribe(new Subscriber<EthGasPrice>() {
                    @Override
                    public void onCompleted() {

                    }

                    @Override
                    public void onError(Throwable a) {
                        e.onError(a);
                    }

                    @Override
                    public void onNext(EthGasPrice ethGasPrice) {
                        BigDecimal bigDecimal = Convert.fromWei(ethGasPrice.getGasPrice().toString(), Convert.Unit.GWEI);
                        e.onNext(bigDecimal.intValue());
                    }
                });

            }
        }).subscribeOn(Schedulers.io())
                .observeOn(AndroidSchedulers.mainThread())
                .subscribe(new Observer<Integer>() {
                    @Override
                    public void onSubscribe(Disposable d) {
                        callBack.start();
                    }

                    @Override
                    public void onNext(Integer gas) {
                        callBack.end(gas);
                    }

                    @Override
                    public void onError(Throwable e) {
                        callBack.error();
                    }

                    @Override
                    public void onComplete() {

                    }
                });
    }

    //    public static void send() {
//        new Thread(new Runnable() {
//            @Override
//            public void run() {
//                try {
//                    Web3j web3 = Web3jFactory.build(new HttpService("https://rinkeby.infura.io/v3/c86557f922384086ac5f500137f8c88a"));  // defaults to http://localhost:8545/
//                    Credentials credentials = WalletUtils.loadCredentials("123456aa", "/storage/emulated/0/ethtoken/keystore_TEST.json");
//                    EthGetTransactionCount ethGetTransactionCount = web3.ethGetTransactionCount(
//                            "0x918b11852933f8a72EDABaB30F24fe0268F6b4CE", DefaultBlockParameterName.LATEST).sendAsync().get();
//                    BigInteger transactionCount = ethGetTransactionCount.getTransactionCount();
//                    RawTransaction etherTransaction = RawTransaction.createEtherTransaction(transactionCount, BigInteger.valueOf(21_000), BigInteger.valueOf(21_000), "0x78d9389ff2270a10ee0c581d0e49ca298349ab8d", BigInteger.valueOf(21_000));
//                    byte[] signedMessage = TransactionEncoder.signMessage(etherTransaction, credentials);
//                    String hexValue = Hex.toHexString(signedMessage);
//                    EthSendTransaction ethSendTransaction = web3.ethSendRawTransaction(hexValue).send();
//                } catch (Exception e) {
//                    e.printStackTrace();
//                }
//            }
//        }).start();
//    }
    public static void getBalance(final CallBack callBack, final String address, final String passsword, final String path) {
        Observable.create(new ObservableOnSubscribe<BigInteger>() {
            @Override
            public void subscribe(ObservableEmitter<BigInteger> observableEmitter) throws Exception {


//                final BenepitToken contract = BenepitToken.load("0x918b11852933f8a72EDABaB30F24fe0268F6b4CE", Web3jUtil.getInstance(passsword).web3,
//                        Web3jUtil.getInstance(passsword).credentials, BigInteger.valueOf(100_000), BigInteger.valueOf(100_000));
                final BenepitToken contract = BenepitToken.load(Constant.MAINADDRESS, Web3jUtil.getInstanceWeb3().web3,
                        Web3jUtil.getInstanceCredentials(passsword, path).credentials, BigInteger.valueOf(100_000), BigInteger.valueOf(100_000));
                BigInteger bigInteger = null;
                try {
                    bigInteger = contract.balanceOf(address).send();
                } catch (Exception e) {
                    e.printStackTrace();
                }
                observableEmitter.onNext(bigInteger);
            }
        }).subscribeOn(Schedulers.io())
                .observeOn(AndroidSchedulers.mainThread())
                .subscribe(new Observer<BigInteger>() {
                    @Override
                    public void onSubscribe(Disposable d) {
                        callBack.start();
                    }

                    @Override
                    public void onNext(BigInteger bigInteger) {
                        callBack.end(bigInteger);
                    }

                    @Override
                    public void onError(Throwable e) {
                        callBack.error();
                    }

                    @Override
                    public void onComplete() {

                    }
                });

    }

    public static void creatWallet(final CallBack callBack, final String psw) {

        Observable.create(new ObservableOnSubscribe<ETHWallet>() {
            @Override
            public void subscribe(ObservableEmitter<ETHWallet> e) throws Exception {
                ETHWallet ethWallet = ETHWalletUtils.generateMnemonic("BebePit", psw);
                e.onNext(ethWallet);
            }
        }).subscribeOn(Schedulers.io())
                .observeOn(AndroidSchedulers.mainThread())
                .subscribe(new Observer<ETHWallet>() {
                    @Override
                    public void onSubscribe(Disposable d) {
                        callBack.start();
                    }

                    @Override
                    public void onNext(ETHWallet wallet) {

                        callBack.end(wallet);
                    }

                    @Override
                    public void onError(Throwable e) {
                        callBack.error();
                    }

                    @Override
                    public void onComplete() {

                    }
                });


    }

    public static void transfer(final String address, final String passsword, final String money, final String gas, final String path, final CallBack<List<String>> callBack) {
        callBack.start();
//        TransactionReceiptProcessor transactionReceiptProcessor =
//                new QueuingTransactionReceiptProcessor(Web3jUtil.getInstanceWeb3().web3, new Callback() {
//                    @Override
//                    public void accept(TransactionReceipt transactionReceipt) {
//                        // process transactionReceipt
//                        Log.e("transactionReceipt",transactionReceipt.toString());
//                    }
//                    @Override
//                    public void exception(Exception exception) {
//                        // handle exception
//                    }},COUNT,POLLING_FREQUENCY);
//        TransactionManager transactionManager = new RawTransactionManager(
//                            Web3jUtil.getInstanceWeb3().web3,  Web3jUtil.getInstanceCredentials(passsword, path).credentials,ChainId.MAINNET , transactionReceiptProcessor);
        Observable.create(new ObservableOnSubscribe<List<String>>() {
            @Override
            public void subscribe(ObservableEmitter<List<String>> observableEmitter) throws Exception {
                final BenepitToken contract = BenepitToken.load(Constant.MAINADDRESS, Web3jUtil.getInstanceWeb3().web3,
                        Web3jUtil.getInstanceCredentials(passsword, path).credentials, new BigInteger(gas), BigInteger.valueOf(100_000));
                BigInteger bigInteger = null;
                try {
//                    RemoteCall<TransactionReceipt> transfer = contract.transfer(address, new BigInteger(money));
//                    TransactionReceipt send = transfer.send();
//
//                    Log.e("send.getBlockHash()",send.getBlockHash());
//                    Log.e("getTransactionHash",send.getTransactionHash());
//                    Log.e("getStatus",send.getStatus());
//                    String transactionHash = send.getTransactionHash();
                    ArrayList<String> list = new ArrayList<>();
//                    list.add(transactionHash);
//                    list.add(money);
//                    list.add(address);

                    // 转账数量 单位: wei
//                    BigInteger wei_value = Convert.toWei(BigDecimal.valueOf(Double.parseDouble(money)), Convert.Unit.ETHER).toBigInteger();
                    // 通过私钥创建转账凭证
//                    Credentials credentials = Credentials.create(pvk);

                    List<Type> types = new ArrayList<>();
                    types.add(new Address(address));
                    types.add(new Uint256(new BigInteger(money)));
                    List<TypeReference<?>> types1 = new ArrayList<>();
                    TypeReference<?> typeTypeReference = TypeReference.create(Type.class);
                    types1.add(typeTypeReference);
                    Function function = new Function(
                            "transfer",
                            types, types1
                    );
                    Credentials credentials = Web3jUtil.getInstanceCredentials(passsword, path).credentials;
                    // 获取交易笔数 nonce
                    BigInteger nonce = getNonce(credentials.getAddress());
                    String encodedFunction = FunctionEncoder.encode(function);

                    RawTransaction rawTransaction = RawTransaction.createTransaction(
                            nonce,
                            new BigInteger(gas),
                            Contract.GAS_LIMIT,
                            Constant.MAINADDRESS,
                            encodedFunction
                    );

                    //签名Transaction，这里要对交易做签名
                    byte[] signMessage = TransactionEncoder.signMessage(rawTransaction, credentials);
                    String hexValue = Numeric.toHexString(signMessage);
                    //发送交易
                    EthSendTransaction sendTx = Web3jUtil.getInstanceWeb3().web3.ethSendRawTransaction(hexValue).sendAsync().get();

                    list.add(sendTx.getTransactionHash());
                    Log.e("send.getTransactionHash", sendTx.getTransactionHash() + "");
                    if (sendTx.getError() != null) {
                        Log.e("getError", sendTx.getError().getMessage() + "");
                        list.add(sendTx.getError().getMessage());
                    } else {
                        list.add(money);
                        list.add(credentials.getAddress());
                    }
                    observableEmitter.onNext(list);
//                    Future<TransactionReceipt> transactionReceiptFuture = transfer.sendAsync()
//                    transfer.observable().subscribe(new Subscriber<TransactionReceipt>() {
//                        @Override
//                        public void onCompleted() {
//
//                        }
//
//                        @Override
//                        public void onError(Throwable e) {
//
//                        }
//
//                        @Override
//                        public void onNext(TransactionReceipt transactionReceipt) {
//
//                            Log.e("transactionReceipt",transactionReceipt.getTransactionHash());
//
//                        }
//                    });
                } catch (Exception e) {
                    observableEmitter.onError(e);
                    e.printStackTrace();
                    Log.e("error", "error");
                }
            }
        }).subscribeOn(Schedulers.io())
                .observeOn(AndroidSchedulers.mainThread())
                .subscribe(new Observer<List<String>>() {
                    @Override
                    public void onSubscribe(Disposable d) {

                    }

                    @Override
                    public void onNext(List<String> string) {
                        callBack.end(string);
                    }

                    @Override
                    public void onError(Throwable e) {
                        callBack.error();
                    }

                    @Override
                    public void onComplete() {

                    }
                });
    }

    public static BigInteger getNonce(String address) throws Exception {
        EthGetTransactionCount count = Web3jUtil.getInstanceWeb3().web3.ethGetTransactionCount(address, DefaultBlockParameterName.LATEST).sendAsync().get();
        return count.getTransactionCount();
    }

    public static void transaction(final String passsword, final String path) {
        Observable.create(new ObservableOnSubscribe<BigInteger>() {
            @Override
//            DefaultBlockParameterName.EARLIEST,DefaultBlockParameterName.LATEST,"0xd27d76a1ba55ce5c0291ccd04febbe793d22ebf4"
            public void subscribe(ObservableEmitter<BigInteger> observableEmitter) throws Exception {
                final BenepitToken contract = BenepitToken.load(Constant.MAINADDRESS, Web3jUtil.getInstanceWeb3().web3,
                        Web3jUtil.getInstanceCredentials(passsword, path).credentials, BigInteger.valueOf(100_000), BigInteger.valueOf(100_000));
                contract.transferEventObservable(new EthFilter()).subscribe(new rx.Observer<BenepitToken.TransferEventResponse>() {
                    @Override
                    public void onCompleted() {

                    }

                    @Override
                    public void onError(Throwable e) {

                    }

                    @Override
                    public void onNext(BenepitToken.TransferEventResponse transferEventResponse) {

                    }
                });
            }
        }).subscribeOn(Schedulers.io())
                .observeOn(AndroidSchedulers.mainThread())
                .subscribe(new Observer<BigInteger>() {
                    @Override
                    public void onSubscribe(Disposable d) {

                    }

                    @Override
                    public void onNext(BigInteger bigInteger) {

                    }

                    @Override
                    public void onError(Throwable e) {

                    }

                    @Override
                    public void onComplete() {

                    }
                });

    }
}
