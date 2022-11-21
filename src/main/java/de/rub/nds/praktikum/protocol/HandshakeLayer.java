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
import javax.naming.Name;

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
        //throw new UnsupportedOperationException("Add code here")

        //server random
        SecureRandom random = context.getSecureRandom();
        byte[] randBytes = new byte[32];
        random.nextBytes(randBytes);
        context.setServerRandom(randBytes);

        //sessionId
        byte[] sessionId;
        sessionId = context.getClientSessionId();
        /*if(!context.getClientSupportedVersions().contains(ProtocolVersion.TLS_1_3)){
            throw new TlsException("Client does not support TLS1.3");
        }*/
        ProtocolVersion v = ProtocolVersion.TLS_1_2; // version in server Hello. Not in extension
        context.setSelectedVersion(ProtocolVersion.TLS_1_3);

        //cipherSuite needs to be filtered here beause of a unit test..?
        boolean found = false;
        for(CipherSuite cs : context.getClientCipherSuiteList()){
            if(context.getServerSupportedCipherSuites().contains(cs)){
                context.setSelectedCiphersuite(cs);
                found = true;
                break;
            }
        }

        CipherSuite suite = context.getSelectedCiphersuite();

        CompressionMethod compressionMethod = CompressionMethod.NULL;

        ArrayList<Extension> extensions = new ArrayList<>();
        //create SupportedVersionExtension
        ArrayList<ProtocolVersion> svel = new ArrayList<>();
        svel.add(ProtocolVersion.TLS_1_3);
        SupportedVersionsExtension sve = new SupportedVersionsExtension(svel);
        extensions.add(sve);

        computeSharedSecret();

        byte[] tmp = new byte[32];
        KeyShareEntry entry = new KeyShareEntry(NamedGroup.ECDH_X25519.getValue(), tmp);
        if(context.getEphemeralPublicKey() != null){
            entry = new KeyShareEntry(NamedGroup.ECDH_X25519.getValue(), context.getEphemeralPublicKey());
        }
        KeyShareExtension kse = new KeyShareExtension(entry);
        extensions.add(kse);

        ServerHello sh = new ServerHello(v, randBytes,sessionId, suite, compressionMethod, extensions);
        ServerHelloSerializer shz = new ServerHelloSerializer(sh);
        byte[] serialized = shz.serialize();
        byte[] length = Util.convertIntToBytes(serialized.length, 3);
        byte[] type = new byte[]{0x02};
        byte[] concat = Util.concatenate(type, length, serialized);
        context.updateDigest(concat);
        try {
            recordLayer.sendData(concat, ProtocolType.HANDSHAKE);
        } catch (Exception e) {
            context.setTlsState(TlsState.ERROR);
            throw new TlsException();
        }
        context.setTlsState(TlsState.NEGOTIATED);
        KeyGenerator.adjustHandshakeSecrets(context);
        KeyGenerator.adjustHandshakeKeys(context);
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
        //throw new UnsupportedOperationException("Add code here");

        ProtocolVersion v = ProtocolVersion.TLS_1_2;
        byte[] sessionId = context.getClientSessionId();
        CipherSuite cs = CipherSuite.TLS_AES_128_GCM_SHA256;
        CompressionMethod cm = CompressionMethod.NULL;

        ArrayList<Extension> extensions = new ArrayList<>();
        //create SupportedVersionExtension
        ArrayList<ProtocolVersion> svel = new ArrayList<>();
        svel.add(ProtocolVersion.TLS_1_3);
        SupportedVersionsExtension sve = new SupportedVersionsExtension(svel);
        extensions.add(sve);
        context.setSelectedVersion(ProtocolVersion.TLS_1_3);

        //create KeyShareExtension
        //byte[] tmp = new byte[2];
        //KeyShareEntry entry = new KeyShareEntry(NamedGroup.ECDH_X25519.getValue(), tmp);
        KeyShareExtension kse = new KeyShareExtension(NamedGroup.ECDH_X25519);
        extensions.add(kse);

        HelloRetryRequest r = new HelloRetryRequest(sessionId, cs, cm, extensions);
        ServerHelloSerializer shz = new ServerHelloSerializer(r);

        byte[] serialized = shz.serialize();
        context.updateDigest(serialized);
        byte[] length = Util.convertIntToBytes(serialized.length, 3);
        byte[] type = new byte[]{0x02};
        byte[] concat = Util.concatenate(type, length, serialized);
        try {
            recordLayer.sendData(concat, ProtocolType.HANDSHAKE);
        }catch(Exception e){
            context.setTlsState(TlsState.ERROR);
            throw new TlsException();
        }
        context.setTlsState(TlsState.AWAIT_RETRY_HELLO_RESPONSE);
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
        //throw new UnsupportedOperationException("Add code here");
        if(stream[0] == (byte)(0x01)){
            //client Hello
            if(context.getTlsState() != TlsState.START &&
                    context.getTlsState() != TlsState.AWAIT_RETRY_HELLO_RESPONSE){
                throw new UnexpectedMessageException();
            }
            byte[] lenBytes = Arrays.copyOfRange(stream, 1, 4);
            int len = Util.convertToInt(lenBytes);
            byte[] payload = Arrays.copyOfRange(stream, 4, 4 + len);
            try {
                //context.updateDigest(stream);
                processClientHello(payload, stream);
            }catch (IOException e){

            }
        }else if(stream[0] == (byte)03){
            //for later .... maybe finished message
        }
    }


    /**
     * Example private function called from processByteStream. Parse handshakePayload, check if payload is
     * correct, handle ClientHello.
     *
     * @param stream a TLS 1.3 handshake message from the client as a byte array
     * @param handshakePayload handshakePayload to be parsed
     */
    private void processClientHello(byte[] handshakePayload, byte[] stream) throws IOException {
        //throw new UnsupportedOperationException("Add code here");
        //parse CH and setup context variables
        context.updateDigest(stream);
        ClientHelloParser chp = new ClientHelloParser(handshakePayload);
        ClientHello ch = chp.parse();
        context.setClientCipherSuiteList(ch.getCiphersuiteList());
        context.setClientCompressions(ch.getCompressionMethodList());
        context.setClientSessionId(ch.getSessionId());
        context.setClientRandom(ch.getRandom());
        for(Extension e : ch.getExtensionList()){
            if(e.getType() == ExtensionType.KEY_SHARE){
                KeyShareExtension ke = (KeyShareExtension)e;
                context.setClientKeyShareEntryList(ke.getEntryList());
            }else if(e.getType() == ExtensionType.SUPPORTED_GROUPS){
                SupportedGroupsExtension ge = (SupportedGroupsExtension)e;
                context.setClientNamedGroupList(ge.getNamedGroupList());
            }else if(e.getType() == ExtensionType.SUPPORTED_VERSIONS){
                SupportedVersionsExtension ve = (SupportedVersionsExtension)e;
                context.setClientSupportedVersions(ve.getSupportedVersions());
            }
        }
        //set the context state according to the variables
        //cipherSuites
        if(context.getClientCipherSuiteList() == null){
            context.setTlsState(TlsState.ERROR);
            return;
        }
        if(!context.getClientCipherSuiteList().contains(CipherSuite.TLS_AES_128_GCM_SHA256)){
            context.setTlsState(TlsState.RETRY_HELLO);
            return;
        }
        //supported versions
        if(context.getClientSupportedVersions() == null){
            context.setTlsState(TlsState.ERROR);
            return;
        }
        if (!context.getClientSupportedVersions().contains(ProtocolVersion.TLS_1_3)){
            context.setTlsState(TlsState.RETRY_HELLO);//? ERROR?
            return;
        }
        //named groups
        if(context.getClientNamedGroupList() == null){
            context.setTlsState(TlsState.ERROR);
            return;
        }
        if(!context.getClientNamedGroupList().contains(NamedGroup.ECDH_X25519)){
            context.setTlsState(TlsState.RETRY_HELLO);
            return;
        }
        if(context.getClientKeyShareEntryList() == null){
            context.setTlsState(TlsState.RETRY_HELLO);
            return;
        }
        boolean keyshareFound = false;
        for(KeyShareEntry e : context.getClientKeyShareEntryList()){
            if(e.getGroup() == NamedGroup.ECDH_X25519){
                keyshareFound = true;
            }
        }
        if(!keyshareFound){
            context.setTlsState(TlsState.RETRY_HELLO);
            return;
        }
        //all fine:) we found cipherSuite, Group and version
        context.setTlsState(TlsState.RECVD_CH);
        KeyGenerator.adjustHandshakeSecrets(context);
    }

    private void computeSharedSecret(){
        byte[] ephemaralPrivKey = new byte[32];
        context.getSecureRandom().nextBytes(ephemaralPrivKey);
        context.setEphemeralPrivateKey(ephemaralPrivKey);

        byte[] ephemeralPubKey = new byte[32];
        X25519.precompute();
        // compute public key (a * G) = ePubKey
        X25519.scalarMultBase(ephemaralPrivKey, 0 , ephemeralPubKey, 0);
        context.setEphemeralPublicKey(ephemeralPubKey);

        //get client pubkey
        byte[] pubKeyClient = new byte[32];
        if(context.getClientKeyShareEntryList() != null)
        for(KeyShareEntry e : context.getClientKeyShareEntryList()){
            if(e.getGroup() == NamedGroup.ECDH_X25519){
                pubKeyClient = e.getKeyShare();
            }
        }

        //compute shared secret
        byte[] sharedSecret = new byte[32];
        X25519.scalarMult(ephemaralPrivKey, 0 , pubKeyClient, 0, sharedSecret, 0);
        context.setSharedEcdheSecret(sharedSecret);
    }
}
