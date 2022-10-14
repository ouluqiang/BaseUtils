package com.olq.base.utils

import android.os.Environment
import com.olq.base.bean.WalletBean
import org.bitcoinj.crypto.*
import org.web3j.abi.FunctionEncoder
import org.web3j.abi.FunctionReturnDecoder
import org.web3j.abi.TypeReference
import org.web3j.abi.datatypes.Address
import org.web3j.abi.datatypes.Function
import org.web3j.abi.datatypes.Type
import org.web3j.abi.datatypes.generated.Uint256
import org.web3j.crypto.*
import org.web3j.protocol.ObjectMapperFactory
import org.web3j.protocol.Web3j
import org.web3j.protocol.core.DefaultBlockParameterName
import org.web3j.protocol.core.methods.request.Transaction
import org.web3j.protocol.core.methods.request.Transaction.createEthCallTransaction
import org.web3j.protocol.core.methods.response.EthCall
import org.web3j.protocol.core.methods.response.Web3ClientVersion
import org.web3j.protocol.http.HttpService
import org.web3j.utils.Convert
import org.web3j.utils.Numeric
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.math.BigInteger
import java.security.SecureRandom
import java.util.*
import java.util.concurrent.ExecutionException


object Web3WalletUtils {

    /**
     * +++私钥==0x8d657ce2fe15dca628a4b0cd775cf364d9c3a5d15316326d4d90e49524ac4e1f
     * +++公钥==0x16d674cdc0cf2d6c778c7156852f787012b2ba1443e8615248594bd3f14066c502c33a195d4b35c400a892f8d3d2abe8f3ece01270e8198c6278caaa46a0a2d
     * +++地址BIP44==f49e08e3f1ab9e9bc78a29a23e15496a5a60cb62
     *
     * tray envelope aunt wine guide stadium sing bullet recall tuna venue claw
     *
     * 订单: 0x83bf69af2d65baec9d22493f61e85f6d6e121879529e83fdbfbb982cc4be4576
     *
     *
     *
     *
     * WalletSecretBean(
     *  privateKey=0x524241e8eb2063cacf4b444567bfb38b771786bb7285388409c6071911fc4c9c
     *  publicKey=0xcfb07166c79e8272360ddf4c15c42b1f8fa8248b2e1e31361758f1a59c89d4112eb80d9980465e158deb129b23deb3156767a3ab6bd4c8f319a1c7cf90918c70
     *  address=0xc718d9ca46c1de8dccd7f0135d63740a68a4f2de
     *  mnemonics=gate stomach thrive vacant when report menu energy wealth street explain club
     *  )
     *
     *
     *
     */

//    val TEXT_M = "tray envelope aunt wine guide stadium sing bullet recall tuna venue claw"
//    val TEXT_KEY = "0x8d657ce2fe15dca628a4b0cd775cf364d9c3a5d15316326d4d90e49524ac4e1f"


//    val WEB3_URL = "https://rinkeby.infura.io/v3/9df29b35c83d4e4c87a8cde2034794f1"



    val WEB3_PASSWORD = "123456"
    val HEX_PREFIX = "0x"
    var web3j: Web3j? = null
    var WEB3_PATH="keystore"
    var WEB3_FILE_NAME=".json"

    /**
     *  1
     *  Test的url
     *  privateKey=0x71fe4d7fa550a1b7020c6b5d446a9bbc987bc892c3eed4681a6dc2f8e2058a6d
     *  publicKey=0x6055b6e115558d0357794187fc5390e7a3c960ae5411f3d82469cf021a4e3a72ca0ca9ee05358099d8a27367866d59bb1dcbb9a33dd622d8a88ff401112d404f
     *  address=0xb474a6088331b2ac12b34ba99cb02af137cc341f
     *  mnemonics=almost deposit brave race drive alien fatigue glory cupboard hope consider despair
     *
     *  2
     *  privateKey=0x9ca3c631d5be9652d422e63657bc0f9b0b06d11d7a42ca0b32f993e5bf1b87d5
     *  publicKey=0xe0f405fef85a81bf9d9f43e7905c675b4ac4333d7f9d29d5c5d9cae64d77ae60f40c9d4863a06a74a86d6cd1270177e892f36dddcac6b9e6756ea587ead68ff1
     *  address=0xaf451ee568a42857efa8602ad95afe47ac8148c4
     *  mnemonics=dynamic wood brisk artefact toddler resource credit salt scatter utility eternal quit
     *
     *  3
     *  privateKey=0xdd041ebf7ef4e01b2d5972fbe67005bcb1693b231389ca844702af3424a4f035
     *  publicKey=0x4b1830195465ee743a879f95ec488d605cb4b78dbf1b22a861f687643f8be8f63363adbbeb165570c6b4c15912d7da8ebc385fb4d62cae7cebce7e2a770bebf
     *  address=0xf7a3bd91f3d69e2912836b1e8cdd0d3d29914db0
     *  mnemonics=service print shiver hood crime pistol size believe smoke same winter fancy
     *
     *  test 有币
     *  privateKey=0xf4daa0afc98eca47204c26a12154ff717b0e87c76a09a4107503013b63cbd4a5
     *  publicKey=0x1c2ffb5eccff885a9ff9269056c874aa049e0b5bfc37bf21ba2dfe9022e554596534931f9c3b8442afcb7d9a203e948214beb5e385434f40890231713ed35417
     *  address=0xc50d27419156ea698023241a722ec579682be095
     *  mnemonics=)
     *  3.710004765666686471
     *
     *  3987840533790000000
     *  0.03
     *
     *
     *  chain_id=18888
     *  contract=0xB1F052E948A63b1c560D569BBd8501B6B6D0690a
     *  gas=210000
     *  gasLimit=8000000
     *  gasPrice=0
     *  msg=
     *  rpc_url=http://18.216.66.9:8545
     *  status=1
     *
     */
    val TEST_URL = "http://web.ifichain.com:8080/dam/app_config"
    val TEST_WEB3_URL = "http://18.216.66.9:8545"

    val INTEGRAL_SHOP_URL=fun (username:String,address:String):String{
        return "http://shop.nextstorage.cn:88/?username=${username}&address=${address}"
    }

    init {
        init(true)
    }

    /**
     * 初始化
     */
    fun init(isAsync:Boolean=false){
        if (web3j ==null) {
            var url = TEST_WEB3_URL
            web3j = sendAsync(isAsync,url, {
                LogUtils.d("web3", "web3连接成功:$url   $it")
            }, {
                LogUtils.d("web3", "web3连接失败:$url   $it")
            })
        }
    }

    /**
     * 本地文件路径
     */
    fun getStoragePath(remotePath: String= WEB3_PATH): File {
        val diskPath = Environment.getExternalStorageDirectory().absolutePath
        val path = diskPath + File.separatorChar + remotePath
        var pathFile=File(path)
        if (!pathFile.exists() && !pathFile.isDirectory()) {
            pathFile.mkdirs()
        }
        return pathFile
    }

    fun getStorageFile(fileName: String,path:String= getStoragePath().absolutePath): File {
        val file = File(path,"${fileName}$WEB3_FILE_NAME")
        return file
    }



    /**
     * 发送连接
     */
    fun sendAsync(isAsync:Boolean=false,url: String, connect: (String) -> Unit, error: (Exception?) -> Unit): Web3j? {
        var web3j = Web3j.build(HttpService(url))
        try {
            var clientVersion:Web3ClientVersion?
            if (isAsync){
                 clientVersion = web3j.web3ClientVersion().sendAsync().get()
            }else {
                 clientVersion = web3j.web3ClientVersion().send()
            }
            if (!clientVersion.hasError()) {
                //Connected
                connect(clientVersion.web3ClientVersion)
                return web3j
            } else {
                //Show Error
                error(null)
            }
        } catch (e: Exception) {
            //Show Error
            error(e)
        }
        return null
    }

    /**
     * 助记词
     */
    fun getMnemonicWords(): String {
        var bytes2 = ByteArray(16)
        var random = SecureRandom();
        random.nextBytes(bytes2);
        var mnemonicCode = MnemonicCode()
        var mnemoniclist = mnemonicCode.toMnemonic(bytes2)
        var mnemonics = ""
        mnemoniclist.forEach {
            mnemonics = mnemonics + "$it "
        }
        LogUtils.d("web3", "助记词：${mnemonics.trim()}")
        return mnemonics.trim()
    }


    /**
     * 根据私钥文件路径加载钱包
     *
     */
    @Throws(CipherException::class)
    fun loadKeystoreWallet(fileName: String): WalletBean? {
        // FIXME: 2018/4/15 替换为自己的钱包路径
//        val phone = CloudApplication.getLoginPhone()
       var file= getStorageFile(fileName)
        if (file.exists()){
            val credentials = WalletUtils.loadCredentials(WEB3_PASSWORD, file)
//            val address = credentials.address
            val ecKeyPair = credentials.ecKeyPair
            val privateKey = Numeric.toHexStringWithPrefix(ecKeyPair.privateKey)
            val publicKey = Numeric.toHexStringWithPrefix(ecKeyPair.publicKey)
            //根据公钥和ecKeyPair获取钱包地址
            val address = Numeric.prependHexPrefix(Keys.getAddress(publicKey))
            var bean = WalletBean(privateKey, publicKey, address, "")
            LogUtils.d("web3", "keystore文件钱包：$bean")
            return bean
        }else{
            return null
        }

    }

    /**
     * 解密keystore 得到私钥
     *
     * @param keystore
     * @param password
     */
    fun decryptKeystoreWallet(keystore: String): String? {
        var privateKey: String? = null
        val objectMapper = ObjectMapperFactory.getObjectMapper()
        try {
            val walletFile = objectMapper.readValue(keystore, WalletFile::class.java)
            var ecKeyPair = Wallet.decrypt(WEB3_PASSWORD, walletFile)
            privateKey = ecKeyPair.privateKey.toString(16)
            println(privateKey)
        } catch (e: CipherException) {
            if ("Invalid password provided" == e.message) {
                println("密码错误")
            }
            e.printStackTrace()
        } catch (e: IOException) {
            e.printStackTrace()
        }
        return privateKey
    }

    /**
     * 助记词导入生成
     * @param mnemonics 助记词
     * @param password 密码（生成私钥用）
     * @return BabelWallet自己创建bean对象，方法返回
     */
    fun loadWalletByMnemonic(mnemonics: String,isKeystore: Boolean=true): WalletBean {
        //2.生成种子
        val seed = MnemonicUtils.generateSeed(mnemonics, "")
        //3. 生成根私钥 root private key 树顶点的master key ；bip32
        val rootPrivateKey = HDKeyDerivation.createMasterPrivateKey(seed)
        // 4. 由根私钥生成 第一个HD 钱包
        val dh = DeterministicHierarchy(rootPrivateKey)

        // 5. 定义父路径 H则是加强 imtoken中的eth钱包进过测试发现使用的是此方式生成 bip44
        val parentPath: List<ChildNumber> = HDUtils.parsePath("M/44H/60H/0H/0")
        val child = dh.deriveChild(parentPath, true, true, ChildNumber(0))
        val privateKeyByte = child.privKeyBytes
        //7.通过私钥生成公私钥对
        val ecKeyPair = ECKeyPair.create(privateKeyByte)
        val privateKey = Numeric.toHexStringWithPrefix(ecKeyPair.privateKey)
        val publicKey = Numeric.toHexStringWithPrefix(ecKeyPair.publicKey)
        //根据公钥和ecKeyPair获取钱包地址
        val address = Numeric.prependHexPrefix(Keys.getAddress(publicKey))
        var bean = WalletBean(privateKey, publicKey, address, mnemonics)
        LogUtils.d("web3", " 助记词钱包：$bean")
        //8.通过密码和钥匙对生成WalletFile也就是keystore的bean类
        if (isKeystore) {
            try {
                var walletFile = Wallet.createLight(WEB3_PASSWORD, ecKeyPair)
                generateKeystore(GsonUtils.toJson(walletFile))
                LogUtils.d("web3", "助记词key钱包: $walletFile ")
            } catch (e: CipherException) {
                e.printStackTrace()
            }
        }
        return bean
    }




    /**
     * 生成钱包keystore文件
     */
    fun generateKeystore(content: String,fileName: String="${System.currentTimeMillis()}") {
//        var path=getStoragePath()
//        val phone = CloudApplication.getLoginPhone()
       var file= getStorageFile(fileName)
        if (!file.exists()) {
            file.createNewFile()
        }
        //        String content = "This is the text content";
        try {
            val fop = FileOutputStream(file)
            // if file doesn't exists, then create it
            // get the content in bytes
            val contentInBytes = content.toByteArray()
            fop.write(contentInBytes)
            fop.flush()
            fop.close()
            println("Done")
        } catch (e: IOException) {
            e.printStackTrace()
        }
    }

    /**
     * 私钥导入
     * //私钥是无法推算出助记词的
     * @param privateKey
     */
    fun loadWalletByPrivateKey(privateKey: String,isKeystore:Boolean=true): WalletBean {
        val credentials = Credentials.create(privateKey)
//        val address = credentials.address
        val ecKeyPair = credentials.ecKeyPair
        val privateKey = Numeric.toHexStringWithPrefix(ecKeyPair.privateKey)
        val publicKey = Numeric.toHexStringWithPrefix(ecKeyPair.publicKey)
        val address = Numeric.prependHexPrefix(Keys.getAddress(publicKey))
        var bean = WalletBean(privateKey, publicKey, address, "")
        LogUtils.d("web3", "私钥钱包：$bean")
        //8.通过密码和钥匙对生成WalletFile也就是keystore的bean类
        if (isKeystore) {
            try {
                var walletFile = Wallet.createLight(WEB3_PASSWORD, ecKeyPair)
                generateKeystore(GsonUtils.toJson(walletFile))
                LogUtils.d("web3", "私钥key钱包: $walletFile ")
            } catch (e: CipherException) {
                e.printStackTrace()
            }
        }
//                var file =  File("Keystore存放的路径");
//        var walletFile = WalletUtils.generateWalletFile("123456",ecKeyPair,file,false);
////        var keystore = FilesUtils.readFileString( File(file, walletFile).getAbsolutePath());
//        println("privateKey:" + ecKeyPair.privateKey.toString(16))
//        println("publicKey:" + ecKeyPair.publicKey.toString(16))
//                System.out.println("keystore:" + keystore);
//        println("address:$address")
        return bean
    }




    /**
     * 余额
     * @param address
     * fromWei 转换小数点值
     * toWei 转换没有小数点币值
     */

    fun walletaBalance(address: String, isEther: Boolean = false): String {
//        Web3j web3 = Web3j.build(new HttpService("节点地址"));  // defaults to http://localhost:8545/
        init()
        if (web3j != null) {
//        String address = "获取余额的地址";
//            var balance: BigInteger? = null
//            try {
            var balance =
                web3j!!.ethGetBalance(address, DefaultBlockParameterName.LATEST).send().balance
            if (isEther) {
                LogUtils.d("web3", "余额:${balance.toString()}")
                return balance.toString()
            } else {
                var balanceWei = fromWei(balance)
//                    Convert.fromWei(balance.toString(), Convert.Unit.ETHER).toPlainString()
                LogUtils.d("web3", "余额:${balanceWei}")
                return balanceWei
            }
            //            BigDecimal c=Convert.toWei(ba,Convert.Unit.ETHER);
//                println("余额：balance:$balance---转换后：$ba----")
//            } catch (e: IOException) {
//                e.printStackTrace()
//            }
        }else{

        }
        return ""
    }


    /**
     * 转账
     *
     */
    fun ethGetTransactionCount(
        from: String,
        privateKey: String,
        to: String,
        value: BigInteger,
        chainId:Long=0,
        block: (String) -> Unit
    ) {
//        try {
//        String from = "转出地址";
//        String to = "转入地址";
//        String privateKey = "你的私钥";
////        BigInteger value = "转出多少";
//        BigInteger value = new BigInteger("112");
////        BigInteger gasPrice = "gas价格";
//        var from = MMKVUtils.getWeb3Address()
//        var privateKey = MMKVUtils.getWeb3PrivateKey()
        val gasPrice: BigInteger = ethGasPrice()
        val gasLimit = BigInteger.valueOf(21000) //单笔转账一般取21000
        //        Web3j web3 = Web3j.build(new HttpService("节点地址"));  // defaults to http://localhost:8545/
        init()
        if (web3j != null) {
            var nonce = web3j!!.ethGetTransactionCount(from, DefaultBlockParameterName.LATEST)
                .send().transactionCount
            val rawTransaction =
                RawTransaction.createTransaction(nonce, gasPrice, gasLimit, to, value, "")
            var ecKeyPair: ECKeyPair? = null
            if (privateKey.startsWith(HEX_PREFIX)) {
                ecKeyPair = ECKeyPair.create(Numeric.decodeQuantity(privateKey))
            } else {
                ecKeyPair = ECKeyPair.create(Numeric.toBigIntNoPrefix(privateKey))
            }
            val credentials = Credentials.create(ecKeyPair)
            val signMessage:ByteArray
            if (chainId==0L){
                 signMessage = TransactionEncoder.signMessage(rawTransaction, credentials)
            }else{
                 signMessage = TransactionEncoder.signMessage(rawTransaction,chainId, credentials)
            }
            val signData = Numeric.toHexString(signMessage)
            val ethSendTransaction = web3j!!.ethSendRawTransaction(signData).send()
            val transactionHash = ethSendTransaction.transactionHash
            LogUtils.d("web3", "交易id hash:$transactionHash")
            //获取到hash就可以查询交易状态了。
            block(transactionHash)
        }
//        } catch (e: IOException) {
//            e.printStackTrace()
//        }
    }

    //    @Throws(IOException::class)
    fun gasPrice(): String {
        return fromWei(ethGasPrice())
    }

    /**
     * * fromWei 转换小数点值
     * toWei 转换没有小数点币值
     */
    fun fromWei(number: BigInteger): String {
        return Convert.fromWei(number.toString(), Convert.Unit.ETHER).toPlainString()
    }
    fun toWei(number: String): BigInteger {
        if (number.isNullOrEmpty()){
            return 0.toBigInteger()
        }else{
            return Convert.toWei(number, Convert.Unit.ETHER).toBigInteger()
        }
    }

    fun ethGasPrice(): BigInteger {
//        try {
        init()
        if (web3j != null) {
            val price = web3j!!.ethGasPrice().send()
            LogUtils.d("web3", "gas价格：${price.gasPrice}")
            return price.gasPrice
        } else {
            return BigInteger("0")
        }
//        } catch (e: IOException) {
//            e.printStackTrace()
//        }
//        return null
    }



    /**
     * 代币转账
     */
    fun transferERC20(
        from: String,
        privateKey: String,
        to: String,
        contractAddress: String,
        chainId: Long,
        value: BigInteger,
        block: (String?) -> Unit
    ) {
//        var from = MMKVUtils.getWeb3Address()
//        var privateKey = MMKVUtils.getWeb3PrivateKey()
        val gasPrice: BigInteger = ethGasPrice()
        val gasLimit: BigInteger = ethGasLimit()
        transferERC20(from, to, privateKey,contractAddress,chainId,gasPrice,gasLimit, value, block)
    }
    fun transferERC20(
        from:String,
        privateKey: String,
        to: String,
        contractAddress: String,
        chainId: Long,
        gasPrice:BigInteger,
        gasLimit:BigInteger,
        value: BigInteger,
        block: (String?) -> Unit
    ) {
//        String from = "转出地址";
//        String to = "转入地址";
//        String privateKey = "你的私钥";
//        BigInteger value = "转出多少";
//        BigInteger value = new BigInteger("10");
//        String contract = "";//合约地址
//        BigInteger gasPrice = "gas价格";
//        BigInteger gasPrice = new BigInteger("1");
//        var contractAddress = MMKVUtils.getWeb3ContractAddress()
//        var chainId = MMKVUtils.getWeb3ChainId()

        //        Web3j web3 = Web3j.build(new HttpService("节点地址"));  // defaults to http://localhost:8545/
//        var nonce: BigInteger? = null
        init()
        try {
            if (web3j != null) {
                var nonce = web3j!!.ethGetTransactionCount(from, DefaultBlockParameterName.LATEST)
                    .send().transactionCount
                val function = org.web3j.abi.datatypes.Function(
                    "transfer",
                    Arrays.asList<Type<*>>(Address(to), Uint256(value)),
                    listOf<TypeReference<*>>(object : TypeReference<Type<*>?>() {})
                )
                val encodedFunction = FunctionEncoder.encode(function)
                val rawTransaction = RawTransaction.createTransaction(
                    nonce,
                    gasPrice,
                    gasLimit,
                    contractAddress,
                    encodedFunction
                )
                var ecKeyPair: ECKeyPair? = null
                if (privateKey.startsWith(HEX_PREFIX)) {
                    ecKeyPair = ECKeyPair.create(Numeric.decodeQuantity(privateKey))
                } else {
                    ecKeyPair = ECKeyPair.create(Numeric.toBigIntNoPrefix(privateKey))
                }
//            val ecKeyPair = ECKeyPair.create(BigInteger(privateKey, 16))
                val credentials = Credentials.create(ecKeyPair)
                val signMessage =
                    TransactionEncoder.signMessage(rawTransaction, chainId.toLong(), credentials)
                val signData = Numeric.toHexString(signMessage)
//            var ethSendTransaction: EthSendTransaction? = null
//            try {
                var ethSendTransaction = web3j!!.ethSendRawTransaction(signData).sendAsync().get()
//            } catch (e: InterruptedException) {
//                e.printStackTrace()
//            } catch (e: ExecutionException) {
//                e.printStackTrace()
//            }
                val transactionHash = ethSendTransaction.transactionHash
                LogUtils.d("web3", "代币交易 hash:$transactionHash")
                //获取到hash就可以查询交易状态了。
                block(transactionHash)
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

     fun ethGasLimit(): BigInteger {
//        var limit = MMKVUtils.getWeb3GasLimit()
        val gasLimit: BigInteger
//        if (limit > 0) {
//            gasLimit = BigInteger.valueOf(limit) //代币转账一般取60000
//        } else {
            gasLimit = BigInteger.valueOf(60000) //代币转账一般取60000
//        }
        return gasLimit
    }


    private const val emptyAddress = "0x0000000000000000000000000000000000000000"

    /**
     * 查询代币发行总量
     *
     * @param web3j
     * @param contractAddress
     * @return
     */
    fun getTokenTotalSupply(web3j: Web3j?, contractAddress: String?): BigInteger {
        init()
        if (web3j != null) {
            val methodName = "totalSupply"
            val fromAddr = emptyAddress
            var totalSupply = BigInteger.ZERO
            val inputParameters: List<Type<*>> = ArrayList()
            val outputParameters: MutableList<TypeReference<*>> = ArrayList()
            val typeReference: TypeReference<Uint256> = object : TypeReference<Uint256>() {}
            outputParameters.add(typeReference)
            val function = Function(methodName, inputParameters, outputParameters)
            val data = FunctionEncoder.encode(function)
            val transaction = createEthCallTransaction(fromAddr, contractAddress, data)
            val ethCall: EthCall
            try {
                ethCall =
                    web3j.ethCall(transaction, DefaultBlockParameterName.LATEST).sendAsync().get()
                val results = FunctionReturnDecoder.decode(ethCall.value, function.outputParameters)
                totalSupply = results[0].value as BigInteger
            } catch (e: InterruptedException) {
                e.printStackTrace()
            } catch (e: ExecutionException) {
                e.printStackTrace()
            }
            return totalSupply
        }
        return BigInteger("")
    }

    /**
     * 查询指定账户
     * 指定 ERC-20 余额
     */
    fun walletaAddressBalance(
        address: String,contractAddress: String, isEther: Boolean = false
    ): String {
        init()
        if (web3j != null) {
            val methodName = "balanceOf"
            val fromAddr = emptyAddress
            var tokenBalance = BigInteger.ZERO
            val inputParameters: MutableList<Type<*>> = ArrayList()
            val userAddress = Address(address)
            inputParameters.add(userAddress)
            val outputParameters: MutableList<TypeReference<*>> = ArrayList()
            val typeReference: TypeReference<Uint256> = object : TypeReference<Uint256>() {}
            outputParameters.add(typeReference)
            val function = org.web3j.abi.datatypes.Function(methodName, inputParameters, outputParameters)
            val data = FunctionEncoder.encode(function)
            val transaction = Transaction.createEthCallTransaction(fromAddr, contractAddress, data)
            val ethCall: EthCall
            try {
                ethCall =
                    web3j!!.ethCall(transaction, DefaultBlockParameterName.LATEST).sendAsync().get()
                val results = FunctionReturnDecoder.decode(ethCall.value, function.outputParameters)
                tokenBalance = results[0].value as BigInteger
                if (isEther){
                    LogUtils.d("web3", "代币余额:${tokenBalance.toString()}")
                    return tokenBalance.toString()
                }else{
                   var balance= fromWei(tokenBalance)
//                    Convert.fromWei(tokenBalance.toString(), Convert.Unit.ETHER).toPlainString()
                    LogUtils.d("web3", "代币余额:${balance.toString()}")
                    return balance
                }

            } catch (e: Exception) {
                e.printStackTrace()
                LogUtils.d("web3", "代币余额错误:${e.toString()}")
            }
        }

        return ""
    }



}
