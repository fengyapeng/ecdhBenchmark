package test;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.security.*;
import java.util.concurrent.TimeUnit;


public class SingleTest {

    private static volatile byte[] staticPublicKey = null;

    private static volatile byte[] staticAesKey = null;


    private static ECParameterSpec ecParams;

    private static KeyFactory kf;
    // thread safe
    private static KeyPairGenerator keyGen;


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
        long start = System.nanoTime();

        for (int i = 0; i < 15000; i++) {

            KeyPair aPair = keyGen.generateKeyPair();
            getPrivateKey(aPair.getPrivate());
            getPublicKey(aPair.getPublic());
        }
        long estimatedTime = System.nanoTime() - start;

        System.out.println(TimeUnit.NANOSECONDS.toMicros(estimatedTime / 15000));
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
}
