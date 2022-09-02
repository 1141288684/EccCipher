package crypto

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.File
import java.io.FileInputStream
import java.security.*
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*
import javax.crypto.Cipher
import kotlin.experimental.and

object Ecc {
    /**
     * @see org.bouncycastle.jcajce.provider.asymmetric.ec.KeyPairGeneratorSpi.ecParameters
     */
    private val KEY_SIZE = 256 //bit
    private val SIGNATURE = "SHA256withECDSA"

    init {
        Security.addProvider(BouncyCastleProvider())
    }

//    private fun printProvider() {
//        val provider: Provider = BouncyCastleProvider()
//        for (service: Provider.Service in provider.services) {
//            println(
//                service.type + ": "
//                        + service.algorithm
//            )
//        }
//    }

//    @JvmStatic
//    fun main(args: Array<String>) {
//        try {
//            val keyPair = keyPair
//            val pubKey = keyPair.public
//            val priKey = keyPair.private
//            //System.out.println("[pubKey]:\n" + getPublicKey(keyPair));
//            //System.out.println("[priKey]:\n" + getPrivateKey(keyPair));
//
//            //测试文本
//            val content = "abcdefg"
//
//            //加密
//            val cipherTxt = encrypt(content.toByteArray(), pubKey)
//            //解密
//            val clearTxt = decrypt(cipherTxt, priKey)
//            //打印
//            println("content:$content")
//            println("cipherTxt[" + cipherTxt.size + "]:" + String(cipherTxt))
//            println("clearTxt:" + String(clearTxt))
//
//            //签名
//            val sign = sign(content, priKey)
//            //验签
//            val ret = verify(content, sign, pubKey)
//            //打印
//            println("content:$content")
//            println("sign[" + sign.size + "]:" + String(sign))
//            println("verify:$ret")
//        } catch (e: Exception) {
//            e.printStackTrace()
//            println("[main]-Exception:$e")
//        }
//    }//BouncyCastle

    //生成秘钥对
    @get:Throws(Exception::class)
    val keyPair: KeyPair
        get() {
            val keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC") //BouncyCastle
            keyPairGenerator.initialize(KEY_SIZE, SecureRandom())
            return keyPairGenerator.generateKeyPair()
        }

//    //获取公钥(Base64编码)
//    fun getPublicKey(keyPair: KeyPair): String {
//        val publicKey = keyPair.public as ECPublicKey
//        val bytes = publicKey.encoded
//        return Base64.getEncoder().encodeToString(bytes)
//    }
//
//    //获取私钥(Base64编码)
//    fun getPrivateKey(keyPair: KeyPair): String {
//        val privateKey = keyPair.private as ECPrivateKey
//        val bytes = privateKey.encoded
//        return Base64.getEncoder().encodeToString(bytes)
//    }

    //公钥加密
    @Throws(Exception::class)
    fun encrypt(content: ByteArray?, pubKey: PublicKey?): ByteArray {
        val cipher = Cipher.getInstance("ECIES", "BC")
        cipher.init(Cipher.ENCRYPT_MODE, pubKey)
        return cipher.doFinal(content)
    }

    //私钥解密
    @Throws(Exception::class)
    fun decrypt(content: ByteArray?, priKey: PrivateKey?): ByteArray {
        val cipher = Cipher.getInstance("ECIES", "BC")
        cipher.init(Cipher.DECRYPT_MODE, priKey)
        return cipher.doFinal(content)
    }

    //私钥签名
    @Throws(Exception::class)
    fun sign(content: String, priKey: PrivateKey?): ByteArray {
        //这里可以从证书中解析出签名算法名称
        //Signature signature = Signature.getInstance(getSigAlgName(pubCert));
        val signature = Signature.getInstance(SIGNATURE) //"SHA256withECDSA"
        signature.initSign(priKey)
        signature.update(content.toByteArray())
        return signature.sign()
    }

    @Throws(Exception::class)
    fun signToString(content: String, priKey: PrivateKey?): String {
        //这里可以从证书中解析出签名算法名称
        //Signature signature = Signature.getInstance(getSigAlgName(pubCert));
        val signature = Signature.getInstance(SIGNATURE) //"SHA256withECDSA"
        signature.initSign(priKey)
        signature.update(content.toByteArray())
        return signature.sign().toHexString()
    }

    //公钥验签
    @Throws(Exception::class)
    fun verify(content: String, sign: ByteArray?, pubKey: PublicKey?): Boolean {
        //这里可以从证书中解析出签名算法名称
        //Signature signature = Signature.getInstance(getSigAlgName(priCert));
        val signature = Signature.getInstance(SIGNATURE) //"SHA256withECDSA"
        signature.initVerify(pubKey)
        signature.update(content.toByteArray())
        return signature.verify(sign)
    }

    @Throws(Exception::class)
    fun verify(content: String, sign: String?, pubKey: PublicKey?): Boolean {
        //这里可以从证书中解析出签名算法名称
        //Signature signature = Signature.getInstance(getSigAlgName(priCert));
        val signature = Signature.getInstance(SIGNATURE) //"SHA256withECDSA"
        signature.initVerify(pubKey)
        signature.update(content.toByteArray())
        return signature.verify(sign?.toByteArray())
    }

    /**
     * 解析证书的签名算法，单独一本公钥或者私钥是无法解析的，证书的内容远不止公钥或者私钥
     */
    @Throws(Exception::class)
    private fun getSigAlgName(certFile: File): String {
        val cf = CertificateFactory.getInstance("X.509", "BC")
        val x509Certificate = cf.generateCertificate(FileInputStream(certFile)) as X509Certificate
        return x509Certificate.sigAlgName
    }
}

fun ByteArray.toHexString():String{
    val s=StringBuilder()
    this.forEach {
        val a: Byte = it
//得到高四位
//得到高四位
        val hi = a.toInt() shr 4 and 0x0F
//得到低四位
//得到低四位
        val lo = a.toInt() and 0x0F
        val hex = CharArray(2)
//如果高四位是大于9的，将其转换成字符a-z, 最后要将得到的转换成字符（char）类型，不然得到的是二进制数
//如果高四位是大于9的，将其转换成字符a-z, 最后要将得到的转换成字符（char）类型，不然得到的是二进制数
        hex[0] = if (hi > 9) (hi - 10 + 'a'.code).toChar() else (hi + '0'.code).toChar()
        hex[1] = if (lo > 9) (lo - 10 + 'a'.code).toChar() else (lo + '0'.code).toChar()
        s.append(String(hex))
    }
//
//    println(String(hex))
    return s.toString()
}
fun String.hexToBytes():ByteArray?{
    return if(this.isEmpty()){
        null
    }else{
        val res=ByteArray(this.length/2)
        var j=0
        var i=0
        while (i<this.length){
            res[j++]=this.substring(i,i+2).toInt(16).toByte()
            i+=2
        }
        res
    }
}




fun main(){
    val k=Ecc.keyPair
    val enc = Ecc.encrypt("123456".toByteArray(),k.public)
    println(String(enc))
    println()
    println(enc.toHexString())
    println()
    println(enc.toHexString().hexToBytes()!!.toHexString())
//    println(enc.toHexString())
    val s = String(Ecc.decrypt(enc,k.private))
    println(s)

}
