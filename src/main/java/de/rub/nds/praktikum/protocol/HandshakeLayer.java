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
        //throw new UnsupportedOperationException("Add code here");

        //server random
        SecureRandom random;
        random = context.getSecureRandom();
        byte[] randBytes = new byte[32];
        random.nextBytes(randBytes);
        context.setServerRandom(randBytes);

        byte[] sessionId;
        ProtocolVersion v = ProtocolVersion.TLS_1_3;

        //if(!context.getClientSupportedVersions().contains(ProtocolVersion.TLS_1_3)){
        //    throw new TlsException("Client does not support TLS1.3");
        //}
        context.setSelectedVersion(v);

        boolean found = false;
        for(CipherSuite cs : context.getClientCipherSuiteList()){
            if(context.getServerSupportedCipherSuites().contains(cs)){
                context.setSelectedCiphersuite(cs);
                found = true;
                break;
            }
        }
        if(!found){
            throw new TlsException("No common ciphersuite");
        }
        CipherSuite suite = context.getSelectedCiphersuite();
        //check whether client sent corresponding keyshare

        CompressionMethod compressionMethod = CompressionMethod.NULL;

        ArrayList<Extension> extensions = new ArrayList<>();
        //create SupportedVersionExtension
        ArrayList<ProtocolVersion> svel = new ArrayList<>();
        svel.add(ProtocolVersion.TLS_1_3);
        SupportedVersionsExtension sve = new SupportedVersionsExtension(svel);
        extensions.add(sve);

        //create KeyShareExtension
        //TODO: DUMMY -> HOW DO I GET THE CORRECT VALUES?
        byte[] tmp = new byte[32];
        KeyShareEntry entry = new KeyShareEntry(NamedGroup.ECDH_X25519.getValue(), tmp);
        KeyShareExtension kse = new KeyShareExtension(entry);
        extensions.add(kse);

        /*if(!context.getTlsState().equals(TlsState.RECVD_CH)){
            context.setTlsState(TlsState.ERROR);
            throw new TlsException("cannot send server hello yet");
        }
        if(!context.getClientSupportedVersions().contains(ProtocolVersion.TLS_1_3)){
            context.setTlsState(TlsState.ERROR);
            throw new TlsException("TLS 1.3 not supported by the client");
         }
         */
        sessionId = context.getClientSessionId();

        ServerHello sh = new ServerHello(v, randBytes,sessionId, suite, compressionMethod, extensions);
        ServerHelloSerializer shz = new ServerHelloSerializer(sh);
        byte[] serialized = shz.serialize();
        byte[] length = Util.convertIntToBytes(serialized.length, 3);
        byte[] type = new byte[]{0x02};
        byte[] concat = Util.concatenate(type, length, serialized);


        try {
            recordLayer.sendData(concat, ProtocolType.HANDSHAKE);
        }catch(Exception e){
            context.setTlsState(TlsState.ERROR);
            throw new TlsException();
        }

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
        CipherSuite cs = context.getSelectedCiphersuite();
        CompressionMethod cm = CompressionMethod.NULL;

        ArrayList<Extension> extensions = new ArrayList<>();
        //create SupportedVersionExtension
        ArrayList<ProtocolVersion> svel = new ArrayList<>();
        svel.add(ProtocolVersion.TLS_1_3);
        SupportedVersionsExtension sve = new SupportedVersionsExtension(svel);
        extensions.add(sve);

        //create KeyShareExtension
        //TODO: DUMMY -> HOW DO I GET THE CORRECT VALUES?
        KeyShareEntry entry = new KeyShareEntry(NamedGroup.ECDH_X25519.getValue(), HelloRetryRequest.randomValue());
        KeyShareExtension kse = new KeyShareExtension(entry);
        extensions.add(kse);

        HelloRetryRequest r = new HelloRetryRequest(sessionId, cs, cm, extensions);
        ServerHelloSerializer shz = new ServerHelloSerializer(r);
        try {
            recordLayer.sendData(shz.serialize(), ProtocolType.HANDSHAKE);
        }catch(Exception e){
            context.setTlsState(TlsState.ERROR);
            throw new TlsException();
        }
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
            if(context.getTlsState() != TlsState.START){
                throw new UnexpectedMessageException();
            }
            byte[] lenBytes = Arrays.copyOfRange(stream, 1, 4);
            int len = Util.convertToInt(lenBytes);
            byte[] payload = Arrays.copyOfRange(stream, 4, 4 + len);
            try {
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
            }else
            if(e.getType() == ExtensionType.SUPPORTED_GROUPS){
                SupportedGroupsExtension ge = (SupportedGroupsExtension)e;
                context.setClientNamedGroupList(ge.getNamedGroupList());
            }else if(e.getType() == ExtensionType.SUPPORTED_VERSIONS){
                SupportedVersionsExtension ve = (SupportedVersionsExtension)e;
                context.setClientSupportedVersions(ve.getSupportedVersions());
            }
        }
        context.setTlsState(TlsState.RECVD_CH);
    }
}
