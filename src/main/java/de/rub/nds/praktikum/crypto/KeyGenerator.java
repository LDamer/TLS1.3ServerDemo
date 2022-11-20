package de.rub.nds.praktikum.crypto;

import de.rub.nds.praktikum.protocol.SessionContext;

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
        //handshake
        byte[] handshakeSecret = HkdFunction.extract(input, context.getSharedEcdheSecret());
        context.setHandshakeSecret(handshakeSecret);

        byte[] clientHandshakeTrafficSecret = HkdFunction.deriveSecret(context.getHandshakeSecret(), HkdFunction.CLIENT_HANDSHAKE_TRAFFIC_SECRET,
                context.getDigest());
        context.setClientHandshakeTrafficSecret(clientHandshakeTrafficSecret);
        byte[] serverHandshakeTrafficSecret = HkdFunction.deriveSecret(context.getHandshakeSecret(), HkdFunction.SERVER_HANDSHAKE_TRAFFIC_SECRET,
                context.getDigest());
        context.setServerHandshakeTrafficSecret(serverHandshakeTrafficSecret);
    }

    /**
     * Computes the handshake keys and sets them in the session context
     *
     * @param context The session context to compute the handshake keys in
     */
    public static void adjustHandshakeKeys(SessionContext context) {
        throw new UnsupportedOperationException("Add code here");

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
        byte[] clientAppSecret = HkdFunction.deriveSecret(context.getMasterSecret(), HkdFunction.CLIENT_APPLICATION_TRAFFIC_SECRET,
                context.getDigest());
        context.setClientApplicationTrafficSecret(clientAppSecret);
        byte[] serverAppSecret = HkdFunction.deriveSecret(context.getMasterSecret(), HkdFunction.SERVER_APPLICATION_TRAFFIC_SECRET,
                context.getDigest());
        context.setClientApplicationTrafficSecret(serverAppSecret);
    }

    /**
     * Computes the application keys and sets them in the session context
     *
     * @param context The session context to compute the application keys in
     */
    public static void adjustApplicationKeys(SessionContext context) {
        throw new UnsupportedOperationException("Add code here");

    }

    /**
     *
     * @param context
     */
    public static void adjustFinishedKeys(SessionContext context) {
        throw new UnsupportedOperationException("Add code here");
    }

    private KeyGenerator() {
    }
}
