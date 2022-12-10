package de.rub.nds.praktikum.crypto;

import de.rub.nds.praktikum.protocol.SessionContext;
import org.bouncycastle.jcajce.provider.symmetric.AES;

import java.nio.charset.StandardCharsets;

/**
 * This is mostly a helper class to collect key computation functions on a
 * single place
 *
 */
public class KeyGenerator {

    private static final int GCM_IV_LENGTH = 12;

    /**
     * Computes the HandshakeSecret, ClientHandshakeTrafficSecret and
     * ServerHandshakeTrafficSecret and sets the according values in the context
     *
     * @param context The context from which to draw the information from and
     * where to set the secrets in
     */
    public static void adjustHandshakeSecrets(SessionContext context) {
        //throw new UnsupportedOperationException("Add code here");
        byte[] earlySecret = HkdFunction.extract(new byte[32],new byte[32]);
        byte[] input = HkdFunction.deriveSecret(earlySecret,HkdFunction.DERIVED, new byte[0]);
        //handshake secret
        byte[] handshakeSecret = HkdFunction.extract(input, context.getSharedEcdheSecret());
        context.setHandshakeSecret(handshakeSecret);
        //handshake client secret
        byte[] clientHandshakeTrafficSecret = HkdFunction.expandLabel(handshakeSecret,
                HkdFunction.CLIENT_HANDSHAKE_TRAFFIC_SECRET, context.getDigest(), 32);
        context.setClientHandshakeTrafficSecret(clientHandshakeTrafficSecret);
        //handshake server secret
        byte[] serverHandshakeTrafficSecret = HkdFunction.expandLabel(handshakeSecret,
                        HkdFunction.SERVER_HANDSHAKE_TRAFFIC_SECRET,context.getDigest(), 32);
        context.setServerHandshakeTrafficSecret(serverHandshakeTrafficSecret);
    }

    /**
     * Computes the handshake keys and sets them in the session context
     *
     * @param context The session context to compute the handshake keys in
     */
    public static void adjustHandshakeKeys(SessionContext context) {
        //throw new UnsupportedOperationException("Add code here");
        byte[] clientWriteKey, clientWriteIV, serverWriteKey, serverWriteIV;
        clientWriteKey = HkdFunction.expandLabel(context.getClientHandshakeTrafficSecret(),
                HkdFunction.KEY, new byte[0], 16);
        context.setClientWriteKey(clientWriteKey);
        clientWriteIV = HkdFunction.expandLabel(context.getClientHandshakeTrafficSecret(),
                HkdFunction.IV, new byte[0], GCM_IV_LENGTH); // 12 = IV len
        context.setClientWriteIv(clientWriteIV);
        serverWriteKey = HkdFunction.expandLabel(context.getServerHandshakeTrafficSecret(),
                HkdFunction.KEY, new byte[0], 16);
        context.setServerWriteKey(serverWriteKey);
        serverWriteIV = HkdFunction.expandLabel(context.getServerHandshakeTrafficSecret(),
                HkdFunction.IV, new byte[0], GCM_IV_LENGTH);
        context.setServerWriteIv(serverWriteIV);
    }

    /**
     * Computes the MasterSecret, ClientApplicationTrafficSecret and
     * ServerApplicationTrafficSecret and sets the according values in the
     * context
     *
     * @param context The context from which to draw the information from and
     * where to set the secrets in
     */
    public static void adjustApplicationSecrets(SessionContext context) {
        //throw new UnsupportedOperationException("Add code here");
        byte[] input = HkdFunction.deriveSecret(context.getHandshakeSecret(),HkdFunction.DERIVED, new byte[0]);
        byte[] masterSecret = HkdFunction.extract(input, new byte[32]);
        context.setMasterSecret(masterSecret);

        byte[] clientAppSecret = HkdFunction.expandLabel(masterSecret, HkdFunction.CLIENT_APPLICATION_TRAFFIC_SECRET,
                context.getDigest(), 32);
        context.setClientApplicationTrafficSecret(clientAppSecret);
        byte[] serverAppSecret = HkdFunction.expandLabel(masterSecret, HkdFunction.SERVER_APPLICATION_TRAFFIC_SECRET,
                context.getDigest(), 32);
        context.setServerApplicationTrafficSecret(serverAppSecret);
    }

    /**
     * Computes the application keys and sets them in the session context
     *
     * @param context The session context to compute the application keys in
     */
    public static void adjustApplicationKeys(SessionContext context) {
        //throw new UnsupportedOperationException("Add code here");
        byte[] clientWrite, clientIV, serverWrite, serverIV;
        clientWrite = HkdFunction.expandLabel(context.getClientApplicationTrafficSecret(),
                HkdFunction.KEY, new byte[0], 16);
        context.setClientWriteKey(clientWrite);
        clientIV = HkdFunction.expandLabel(context.getClientApplicationTrafficSecret(),
                HkdFunction.IV, new byte[0], 12); // 12 = IV len
        context.setClientWriteIv(clientIV);
        serverIV = HkdFunction.expandLabel(context.getServerApplicationTrafficSecret(),
                HkdFunction.IV, new byte[0], 12);
        context.setServerWriteIv(serverIV);
        serverWrite = HkdFunction.expandLabel(context.getServerApplicationTrafficSecret(),
                HkdFunction.KEY, new byte[0], 16);
        context.setServerWriteKey(serverWrite);
    }

    /**
     *
     * @param context
     */
    public static void adjustFinishedKeys(SessionContext context) {
        //throw new UnsupportedOperationException("Add code here");
        byte[] clientFinished = HkdFunction.expandLabel(context.getClientHandshakeTrafficSecret(),
                HkdFunction.FINISHED, new byte[0], 32);
        byte[] serverFinished= HkdFunction.expandLabel(context.getServerHandshakeTrafficSecret(),
                HkdFunction.FINISHED, new byte[0], 32);

        context.setClientFinishedKey(clientFinished);
        context.setServerFinishedKey(serverFinished);
    }


    private KeyGenerator() {
    }
}
