package de.rub.nds.praktikum.crypto;

import de.rub.nds.praktikum.exception.TlsException;
import de.rub.nds.praktikum.util.Util;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.dsig.spec.HMACParameterSpec;

/**
 * HKDF-Function which is used in TLS 1.3 for the key derivation
 */
public class HkdFunction {

    /**
     * Key label
     */
    public static final String KEY = "key";

    /**
     * IV label
     */
    public static final String IV = "iv";

    /**
     * Finished labal
     */
    public static final String FINISHED = "finished";

    /**
     * Derived label
     */
    public static final String DERIVED = "derived";

    /**
     * client handshake traffic secret label
     */
    public static final String CLIENT_HANDSHAKE_TRAFFIC_SECRET = "c hs traffic";

    /**
     * server handshake traffic secret label
     */
    public static final String SERVER_HANDSHAKE_TRAFFIC_SECRET = "s hs traffic";

    /**
     * client application traffic secret label
     */
    public static final String CLIENT_APPLICATION_TRAFFIC_SECRET = "c ap traffic";

    /**
     * server application traffic secret label
     */
    public static final String SERVER_APPLICATION_TRAFFIC_SECRET = "s ap traffic";

    private static byte[] hmacSHA256(byte[] salt, byte[] data){
        SecretKey sk = new SecretKeySpec(salt, "HmacSHA256");
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(sk);
            return mac.doFinal(data);
        } catch (Exception e){
            throw new TlsException("didnt find SHA256 at provider lul");
        }
    }

    /**
     * Computes HKDF-Extract output as defined in RFC 5869
     *
     * @param salt The Salt
     * @param ikm The IKM
     * @return The HKDF-Extracted output
     */
    public static byte[] extract(byte[] salt, byte[] ikm) {
        //throw new UnsupportedOperationException("Add code here");
        try {
            if(salt.length <= 0){
                salt = new byte[32];
            }
            return hmacSHA256(salt, ikm);

        }catch (Exception e){
            throw new TlsException("SHA 256 not found at provider luuuul");
        }

    }

    /**
     * Computes HKDF-Expand output as defined in RFC 5869
     *
     * @param prk THE prk
     * @param info The info
     * @param outLen The output Length
     * @return The expanded bytes
     */
    public static byte[] expand(byte[] prk, byte[] info, int outLen) {
        //throw new UnsupportedOperationException("Add code here");
        byte[] t = new byte[0];
        byte[] okm = new byte[0];
        int i = 1;
        while(okm.length < outLen){
            byte[] input = Util.concatenate(t, info, new byte[]{(byte)i});
            t = hmacSHA256(prk, input);
            okm = Util.concatenate(okm, t);
            i++;
        }
        return Arrays.copyOfRange(okm, 0, outLen);
    }

    /**
     * Computes the HKDF-Label as defined in TLS 1.3
     */
    private static byte[] labelEncoder(byte[] hashValue, String labelIn, int outLen) {
        //throw new UnsupportedOperationException("Add code here");
        byte[] res = new byte[0];
        byte[] outLenBytes = Util.convertIntToBytes(outLen, 2);

        byte[] labelLenBytes = Util.convertIntToBytes(("tls13 " + labelIn).length(),1);
        byte[] tlsLabelBytes = "tls13 ".getBytes(StandardCharsets.UTF_8);
        byte[] labelInBytes = labelIn.getBytes(StandardCharsets.UTF_8);
        byte[] hashLenBytes = Util.convertIntToBytes(hashValue.length, 1);
        return Util.concatenate(outLenBytes, labelLenBytes, tlsLabelBytes, labelInBytes, hashLenBytes, hashValue);
    }

    public static byte[] sha256(byte[] data){
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            return sha256.digest(data);
        }catch (Exception e){
            throw new TlsException("no sha256 found at provider lol");
        }
    }

    /**
     * Computes Derive-Secret output as defined in TLS 1.3
     *
     * @param prk the provided prk
     * @param labelIn the label
     * @param toHash the data that should be hashed
     * @return the derived secret
     */
    public static byte[] deriveSecret(byte[] prk, String labelIn, byte[] toHash) {
        //throw new UnsupportedOperationException("Add code here");
        byte[] digest = sha256(toHash);
        return expandLabel(prk, labelIn, digest, 32);
    }

    /**
     * Computes HKDF-Expand-Label output as defined in TLS 1.3. This should use
     * the labelEncoder function
     *
     * @param prk The Prk
     * @param labelIn The InputLabel
     * @param hashValue The HashValue
     * @param outLen The output length
     * @return The expanded Label bytes
     */
    public static byte[] expandLabel(byte[] prk, String labelIn, byte[] hashValue, int outLen) {
        //throw new UnsupportedOperationException("Add code here");
        byte[] info = labelEncoder(hashValue,labelIn, outLen);
        return expand(prk, info, outLen);
    }

    private HkdFunction() {
    }
}
