package test;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)// 测试方法平均执行时间
@OutputTimeUnit(TimeUnit.MICROSECONDS)// 输出结果的时间粒度为微秒
@State(Scope.Benchmark) // 每个测试线程一个实例
@Warmup(iterations = 2)
@Measurement(iterations = 3)
@Fork(value = 1, jvmArgs = {"-Xms1G", "-Xmx1G"})
//@Threads(10)
public class ECDHBenchmarkTest {

    private static volatile byte[] staticPublicKey = null;

    private static volatile byte[] staticAesKey = null;


    private static ECParameterSpec ecParams;

    private static KeyFactory kf;
    // thread safe
    private static KeyPairGenerator keyGen;

    @Param({"100", "500", "1000", "5000", "10000"})
    private long length;


    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            System.out.println("security provider BC not found, add BouncyCastleProvider");
            Security.addProvider(new BouncyCastleProvider());
            try {
                ecParams = ECNamedCurveTable.getParameterSpec("secp256r1");
//                ECGenParameterSpec ecSpec = new ECGenParameterSpec("prime192v1");
//                ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");

                kf = KeyFactory.getInstance("ECDH", "BC");
                keyGen = KeyPairGenerator.getInstance("ECDH");
                keyGen.initialize(ecParams);
                Cipher aesCipher = Cipher.getInstance("AES/ECB/NoPadding", "BC");

                KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
                keyGen.init(256);
                staticAesKey = keyGen.generateKey().getEncoded();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
            } catch (InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) throws Exception {
        // 可以通过注解
        Options opt = new OptionsBuilder()
                .include(ECDHBenchmarkTest.class.getSimpleName())
//                .warmupIterations(3) // 预热3次
//                .measurementIterations(2).measurementTime(TimeValue.valueOf("1s")) // 运行5次，每次10秒
//                .threads(10) // 10线程并发
//                .forks(2)
                .build();

        new Runner(opt).run();

    }

    @Setup
    public void generateEcdhPairKey() throws Exception {
        KeyPair aPair = keyGen.generateKeyPair();
        staticPublicKey = getPublicKey(aPair.getPublic());
    }


    @Benchmark
    public void generateECDHKeyPair() throws Exception {
        for (int i = 0; i < length; i++) {
            KeyPair aPair = keyGen.generateKeyPair();
            getPrivateKey(aPair.getPrivate());
            getPublicKey(aPair.getPublic());
        }
    }

    @Benchmark
    public void generateECDHSecret() throws Exception {
        for (int i = 0; i < length; i++) {
            KeyPair aPair = keyGen.generateKeyPair();
            generateSecret(getPrivateKey(aPair.getPrivate()), staticPublicKey);
        }
    }

    @Benchmark
    public void singleAes() throws Exception {
        for (int i = 0; i < length; i++) {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
            String abc = "1234567890";
            cipher.init(Cipher.ENCRYPT_MODE, loadAesSecretKey(staticAesKey));
            cipher.doFinal(abc.getBytes());
        }
    }

    @Benchmark
    public void ecdhAes() throws Exception {
        for (int i = 0; i < length; i++) {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
            String abc = "1234567890";
            KeyPair aPair = keyGen.generateKeyPair();
            byte[] keys = generateSecret(getPrivateKey(aPair.getPrivate()), staticPublicKey);
            cipher.init(Cipher.ENCRYPT_MODE, loadAesSecretKey(keys));
            cipher.doFinal(abc.getBytes());
        }
    }


    public static byte[] getPublicKey(PublicKey key) throws Exception {
        //return key.getEncoded();
        ECPublicKey eckey = (ECPublicKey) key;
        return eckey.getQ().getEncoded(false);
    }

    public static PublicKey loadPublicKey(byte[] data) throws Exception {
		/*KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
		return kf.generatePublic(new X509EncodedKeySpec(data));*/

        ECPublicKeySpec pubKey = new ECPublicKeySpec(
                ecParams.getCurve().decodePoint(data), ecParams);
        return kf.generatePublic(pubKey);
    }

    public static byte[] getPrivateKey(PrivateKey key) throws Exception {
        //return key.getEncoded();

        ECPrivateKey eckey = (ECPrivateKey) key;
        return eckey.getD().toByteArray();
    }

    public static PrivateKey loadPrivateKey(byte[] data) throws Exception {
        //KeyFactory kf = KeyFactory.getInstance("ECDH", "BC");
        //return kf.generatePrivate(new PKCS8EncodedKeySpec(data));


        ECPrivateKeySpec prvkey = new ECPrivateKeySpec(new BigInteger(data), ecParams);
        return kf.generatePrivate(prvkey);
    }

    public static SecretKey loadAesSecretKey(byte[] keys) {
        SecretKeySpec key = new SecretKeySpec(keys, "AES");
        return key;
    }

    public static byte[] generateSecret(byte[] dataPrv, byte[] dataPub) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH", "BC");
        ka.init(loadPrivateKey(dataPrv));
        ka.doPhase(loadPublicKey(dataPub), true);
        return ka.generateSecret();
    }
}
