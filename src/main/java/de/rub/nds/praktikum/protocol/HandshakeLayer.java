package de.rub.nds.praktikum.protocol;

import de.rub.nds.praktikum.constants.CipherSuite;
import de.rub.nds.praktikum.constants.CompressionMethod;
import de.rub.nds.praktikum.constants.ExtensionType;
import de.rub.nds.praktikum.constants.FieldLength;
import de.rub.nds.praktikum.constants.HandshakeMessageType;
import de.rub.nds.praktikum.constants.NamedGroup;
import de.rub.nds.praktikum.constants.ProtocolType;
import de.rub.nds.praktikum.constants.ProtocolVersion;
import de.rub.nds.praktikum.constants.SignatureAndHashAlgorithm;
import de.rub.nds.praktikum.constants.TlsState;
import de.rub.nds.praktikum.crypto.KeyGenerator;
import de.rub.nds.praktikum.exception.ParserException;
import de.rub.nds.praktikum.exception.TlsException;
import de.rub.nds.praktikum.exception.UnexpectedMessageException;
import de.rub.nds.praktikum.messages.CertificateMessage;
import de.rub.nds.praktikum.messages.CertificateMessageSerializer;
import de.rub.nds.praktikum.messages.CertificateVerify;
import de.rub.nds.praktikum.messages.CertificateVerifySerializer;
import de.rub.nds.praktikum.messages.ClientHello;
import de.rub.nds.praktikum.messages.ClientHelloParser;
import de.rub.nds.praktikum.messages.EncryptedExtensions;
import de.rub.nds.praktikum.messages.EncryptedExtensionsSerializer;
import de.rub.nds.praktikum.messages.Finished;
import de.rub.nds.praktikum.messages.FinishedParser;
import de.rub.nds.praktikum.messages.FinishedSerializer;
import de.rub.nds.praktikum.messages.HelloRetryRequest;
import de.rub.nds.praktikum.messages.ServerHello;
import de.rub.nds.praktikum.messages.ServerHelloSerializer;
import de.rub.nds.praktikum.messages.extensions.Extension;
import de.rub.nds.praktikum.messages.extensions.KeyShareEntry;
import de.rub.nds.praktikum.messages.extensions.KeyShareExtension;
import de.rub.nds.praktikum.messages.extensions.SupportedGroupsExtension;
import de.rub.nds.praktikum.messages.extensions.SupportedSignaturesAlgorithmExtension;
import de.rub.nds.praktikum.messages.extensions.SupportedVersionsExtension;
import de.rub.nds.praktikum.util.Util;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.math.ec.rfc7748.X25519;

/**
 * The handshake layer is responsible for the exchange of handshake messages
 * which are ultimately used to create the connection
 */
public class HandshakeLayer extends TlsSubProtocol {

    private final SessionContext context;

    private final RecordLayer recordLayer;

    /**
     * Constructor
     *
     * @param context     The SessionContext for which this handshake layer should
     *                    be constructed
     * @param recordLayer The record layer that should be used by this handshake
     *                    layer
     */
    public HandshakeLayer(SessionContext context, RecordLayer recordLayer) {
        super(ProtocolType.HANDSHAKE.getByteValue());
        this.context = context;
        this.recordLayer = recordLayer;
    }

    /**
     * Creates a ServerHelloMessage, serializes it sends via the RecordLayer and
     * updates the context accordingly. The message should contain a supported
     * versions extension and a keyshare extension.
     *
     * *IMPORTANT* In this course you have to add these extensions in exactly
     * this order or you will not pass the unit tests!!! *IMPORTANT*
     */
    public void sendServerHello() {
        throw new UnsupportedOperationException("Add code here");
        /*
        SecureRandom random;
        byte[] sessionId;
        ProtocolVersion v = ProtocolVersion.TLS_1_3;
        CipherSuite suite = CipherSuite.TLS_AES_128_GCM_SHA256;
        CompressionMethod compressionMethod = CompressionMethod.NULL;

        ArrayList<Extension> extensions = new ArrayList<>();
        //create SupportedVersionExtension
        ArrayList<ProtocolVersion> svel = new ArrayList<>();
        svel.add(ProtocolVersion.TLS_1_3);
        SupportedVersionsExtension sve = new SupportedVersionsExtension(svel);
        extensions.add(sve);

        //create KeyShareExtension
        //TODO: THIS IS A DUMMY EXTENSION ONLY!
        KeyShareExtension kse = new KeyShareExtension(NamedGroup.ECDH_X25519);
        extensions.add(kse);

        if(!context.getTlsState().equals(TlsState.RECVD_CH)){
            context.setTlsState(TlsState.ERROR);
            throw new TlsException("cannot send server hello yet");
        }
        if(!context.getClientSupportedVersions().contains(ProtocolVersion.TLS_1_3)){
            context.setTlsState(TlsState.ERROR);
            throw new TlsException("TLS 1.3 not supported by the client");

        }

        //ArrayList<NamedGroup> clientGroups = (ArrayList<NamedGroup>) context.getClientNamedGroupList();
        //TODO: find groups server supports
        //for(NamedGroup g : clientGroups){
        //}


        //suppose we can send the serverHello now

        random = context.getSecureRandom();
        //sessionId = Util.hexStringToByteArray("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8\n" +
        //        "339c");// DUMMY FOR MIDDLE BOXES

        sessionId = context.getClientSessionId();

        ServerHello sh = new ServerHello(v, Util.hexStringToByteArray(random.toString()), sessionId, suite, compressionMethod, extensions);
        ServerHelloSerializer shz = new ServerHelloSerializer(sh);
        try {
            recordLayer.sendData(shz.serialize(), ProtocolType.HANDSHAKE);
        }catch(Exception e){
            context.setTlsState(TlsState.ERROR);
            throw new TlsException();
        }
        */
    }

    /**
     * Creates a HelloRetryRequest, serializes it sends via the RecordLayer and
     * updates the context accordingly. The message should contain a supported
     * versions extension and the keyshare extension.
     *
     * *IMPORTANT* In this course you have to add these extensions in exactly
     * this order or you will not pass the unit tests!!! *IMPORTANT*
     */
    public void sendHelloRetryRequest() {
        throw new UnsupportedOperationException("Add code here");
    }

    /**
     * Creates a EncryptedExtensions message, serializes it sends via the
     * RecordLayer and updates the context accordingly.
     */
    public void sendEncryptedExtensions() {
        throw new UnsupportedOperationException("Add code here");
    }

    /**
     * Creates a Certificate message with the certificate chain from the
     * context, serializes it sends via the RecordLayer and updates the context
     * accordingly.
     */
    public void sendCertificates() {
        throw new UnsupportedOperationException("Add code here");
    }

    /**
     * Creates a CertificateVerify message, serializes it sends via the
     * RecordLayer and updates the context accordingly.
     */
    public void sendCertificateVerify() {
        throw new UnsupportedOperationException("Add code here");
    }

    /**
     * Creates a Finished message, serializes it sends via the RecordLayer and
     * updates the context accordingly.
     */
    public void sendFinished() {
        throw new UnsupportedOperationException("Add code here");
    }

    /**
     * Analyze byte stream and parse handshake messages. If a proper message is
     * received, update the TLS context. Consider creating several private
     * functions for processing different handshake messages.
     *
     * @param stream a TLS 1.3 handshake message from the client as a byte array
     */
    @Override
    public void processByteStream(byte[] stream) {
        throw new UnsupportedOperationException("Add code here");
    }


    /**
     * Example private function called from processByteStream. Parse handshakePayload, check if payload is
     * correct, handle ClientHello.
     *
     * @param stream a TLS 1.3 handshake message from the client as a byte array
     * @param handshakePayload handshakePayload to be parsed
     */
    private void processClientHello(byte[] handshakePayload, byte[] stream) throws IOException {
        throw new UnsupportedOperationException("Add code here");
    }
}
