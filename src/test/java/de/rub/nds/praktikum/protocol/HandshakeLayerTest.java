package de.rub.nds.praktikum.protocol;

import de.rub.nds.praktikum.constants.CipherSuite;
import de.rub.nds.praktikum.constants.CompressionMethod;
import de.rub.nds.praktikum.constants.NamedGroup;
import de.rub.nds.praktikum.constants.ProtocolType;
import de.rub.nds.praktikum.constants.ProtocolVersion;
import de.rub.nds.praktikum.constants.SignatureAndHashAlgorithm;
import de.rub.nds.praktikum.constants.TlsState;
import de.rub.nds.praktikum.crypto.KeyGenerator;
import de.rub.nds.praktikum.exception.TlsException;
import de.rub.nds.praktikum.exception.UnexpectedMessageException;
import de.rub.nds.praktikum.messages.Parser;
import de.rub.nds.praktikum.messages.extensions.KeyShareEntry;
import de.rub.nds.praktikum.records.Record;
import de.rub.nds.praktikum.records.RecordParser;
import de.rub.nds.praktikum.util.NotSecureRandom;
import de.rub.nds.praktikum.util.Util;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.TestRandomData;
import org.junit.Assert;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

/**
 *
 */
public class HandshakeLayerTest {

    private HandshakeLayer handshakeLayer;
    private ByteArrayOutputStream outputStream;
    private ByteArrayInputStream inputStream;
    private SessionContext context;
    private RecordLayer recordLayer;

    public HandshakeLayerTest() {
    }

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        context = spy(new SessionContext(Certificate.EMPTY_CHAIN, null));
        outputStream = new ByteArrayOutputStream();
        inputStream = new ByteArrayInputStream(Util.hexStringToByteArray("0123456789"));
        recordLayer = new RecordLayer(outputStream, inputStream, context, 0);
    }

    @Test
    @Category(de.rub.nds.praktikum.Aufgabe2.class)
    public void testSendServerHello() {
        when(context.getSecureRandom()).thenReturn(new NotSecureRandom((byte) 0xBB));

        List<CipherSuite> suiteList = new LinkedList<>();
        suiteList.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        List<KeyShareEntry> keyShareEntryList = new LinkedList<>();
        keyShareEntryList.add(new KeyShareEntry(NamedGroup.ECDH_X25519.getValue(), Util.hexStringToByteArray("AABBCC00112200AABBCC00112200AABBCC00112200AABBCC0011220000001122")));
        context.setClientCipherSuiteList(suiteList);
        context.setClientKeyShareEntryList(keyShareEntryList);
        context.setClientSessionId(Util.hexStringToByteArray("AABBCCDDEEFF0011AABBCCDDEEFF0011AABBCCDDEEFF0011AABBCCDDEEFF0011"));
        handshakeLayer = new HandshakeLayer(context, recordLayer);
        assertNull(context.getServerRandom());
        assertNull(context.getSelectedCiphersuite());
        handshakeLayer.sendServerHello();
        byte[] serverHelloBytes = outputStream.toByteArray();
        assertEquals("ServerHello should be 127 Bytes long",127, serverHelloBytes.length);//We only implement a minimal version of the SH with only one supported named group - it should contain exactly 127 bytes (with record header)
        //Since we do not have a SH parser we need to create one manually
        RecordParser parser = new RecordParser(serverHelloBytes);
        Record parsedRecord = parser.parse();
        Assert.assertEquals(ProtocolType.HANDSHAKE.getByteValue(), parsedRecord.getType());
        Assert.assertArrayEquals(Util.hexStringToByteArray("0303"), parsedRecord.getVersion());
        //RecorData is 5 Bytes shorter than Record (1Byte=RecordType, 2Byte=TlsVersion, 2Byte=DataLen)
        Assert.assertEquals("The data should have a length of 122 Bytes",0x7A, parsedRecord.getData().length);
        Parser tempParser = new Parser(parsedRecord.getData()) {
            @Override
            public Object parse() {
                assertEquals("The SH",2, parseByteField()); //type
                assertEquals(0x76, parseIntField(3)); //length
                Assert.assertArrayEquals(ProtocolVersion.TLS_1_2.getValue(), parseByteArrayField(2)); //version
                assertArrayEquals("Tests if the Random is 0xBBBB... This should be the case because we use a rigged random number generator in this test."
                        + "If you do not have rigged random numbers here, you did not use SecureRandom from the Context.", Util.hexStringToByteArray("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"), parseByteArrayField(32));
                assertEquals(32, parseByteField()); //session id length
                Assert.assertArrayEquals(Util.hexStringToByteArray("AABBCCDDEEFF0011AABBCCDDEEFF0011AABBCCDDEEFF0011AABBCCDDEEFF0011"), parseByteArrayField(32)); //sessionID
                Assert.assertArrayEquals(CipherSuite.TLS_AES_128_GCM_SHA256.getValue(), parseByteArrayField(2)); //ciphersuite
                Assert.assertArrayEquals(new byte[]{0x00}, parseByteArrayField(1)); //compression
                assertEquals(0x002e, parseIntField(2)); //Extensions
                //we do not parse extension bytes - since they re somewhat random / random order
                return null;
            }
        };
        tempParser.parse();
        assertEquals("Negotiated version did not make it into the Context", ProtocolVersion.TLS_1_3, context.getSelectedVersion()); //This should be true since we only support TLS 1.3
        assertEquals("CipherSuite did not make it into the Context", CipherSuite.TLS_AES_128_GCM_SHA256, context.getSelectedCiphersuite()); //this should be true since we only support this one
        assertArrayEquals("Random did not make it into the Context", Util.hexStringToByteArray("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"), context.getServerRandom());
    }

    @Test
    @Category(de.rub.nds.praktikum.Aufgabe3.class)
    public void testSendServerHelloTask3() {
        testSendServerHello();
        //The client pk is AABBCC00112200AABBCC00112200AABBCC00112200AABBCC0011220000001122
        //Our private key is BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB since we used the rigged random number generator
        assertArrayEquals("The private key has to be derived from the random number generator from the context", Util.hexStringToByteArray("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"), context.getEphemeralPrivateKey());
        assertArrayEquals("The computed public key accordingly is: 6b0b616d718e53691236d3be3ce6d44f9d28836426d81305d131f488206f8d2b", Util.hexStringToByteArray("6b0b616d718e53691236d3be3ce6d44f9d28836426d81305d131f488206f8d2b"), context.getEphemeralPublicKey());
        assertArrayEquals("The session secret is the pruduct of the server private key and the client public key",Util.hexStringToByteArray("a82118fedf0b79e0d8c079c98b19eae42bee58473359158cfaecf0057b9e2069"), context.getSharedEcdheSecret());
        assertArrayEquals("This must be extract from the derivedSecret and the sharedSecret",Util.hexStringToByteArray("f72e2d3fd3d4cf8d0d3047ad318636b360803999a0f30fd6bd039bed4f3d34bf"), context.getHandshakeSecret());
        assertArrayEquals("This Secret must contain the digest from all messages",Util.hexStringToByteArray("a35189b7cd84644fbe9396d044beeb5eb8f4938f110d5479d7b27613db4cc286"), context.getClientHandshakeTrafficSecret());
        assertArrayEquals("This Secret must contain the digest from all messages",Util.hexStringToByteArray("c6703594ee511cad7b13f789bb7a2ca56307b612d491c78410ff0b826a388ba4"), context.getServerHandshakeTrafficSecret());
        assertArrayEquals("This must be expanded from the ClientHandshakeTrafficSecret",Util.hexStringToByteArray("1d6ff896fe890d88e537331c"), context.getClientWriteIv());
        assertArrayEquals("This must be expanded from the ClientHandshakeTrafficSecret",Util.hexStringToByteArray("6d8967a2c6ca1c90c1d43cf14a4f398a"), context.getClientWriteKey());
        assertArrayEquals("This must be expanded from the ServerHandshakeTrafficSecret",Util.hexStringToByteArray("8faca40fba158ad028f53586"), context.getServerWriteIv());
        assertArrayEquals("This must be expanded from the ServerHandshakeTrafficSecret",Util.hexStringToByteArray("15fcb979f24d6af56d1bb764f6324d1d"), context.getServerWriteKey());
        assertArrayEquals("The Digest does not equal - did you foret to update it?", Util.hexStringToByteArray("434a0a77b0a59cfa92554014c149ccc75b46dffe43fdd4e15f0b812b28eaab99"), context.getDigest());
    }

    @Test
    @Category(de.rub.nds.praktikum.Aufgabe4.class)
    public void testSendEncryptedExtensionsTask4() {
        handshakeLayer = new HandshakeLayer(context, recordLayer);
        handshakeLayer.sendEncryptedExtensions();
        byte[] encryptedExtensionBytes = outputStream.toByteArray();
        // 5 Byte Record Header +1 Byte Type of Handshake Message + 3 byte len + 2Byte EncryptedExtension
        assertEquals("This message must be 11 bytes long",11, encryptedExtensionBytes.length);//We send an empty encryptedExtension message in a single record
        RecordParser parser = new RecordParser(encryptedExtensionBytes);
        Record parsedRecord = parser.parse();
        Assert.assertEquals("Without the reocrd header the data must be 6 bytes long",6, parsedRecord.getData().length);
        Assert.assertArrayEquals("The Record version is not TLS 1.2",Util.hexStringToByteArray("0303"), parsedRecord.getVersion());
        Assert.assertEquals("The Record Type is not TLS 1.2",ProtocolType.HANDSHAKE.getByteValue(), parsedRecord.getType());
        Parser tempParser = new Parser(parsedRecord.getData()) {
            @Override
            public Object parse() {
                Assert.assertArrayEquals("The Handshake message type must be 8 and it contains only 0000",Util.hexStringToByteArray("080000020000"), parseByteArrayField(6));
                return null;
            }
        };
        tempParser.parse();
        assertArrayEquals("The Digest does not equal - did you foret to update it?", Util.hexStringToByteArray("9f179c787269b4523675acc0ec2be4308a595315cd451be2b16a63a780679fe9"), context.getDigest());
    }

    @Test
    @Category(de.rub.nds.praktikum.Aufgabe2.class)
    public void testSendHelloRetryRequest() {
        List<CipherSuite> suiteList = new LinkedList<>();
        suiteList.add(CipherSuite.TLS_AES_128_GCM_SHA256);
        context.setClientCipherSuiteList(suiteList);
        context.setClientSessionId(Util.hexStringToByteArray("AABBCCDDEEFF0011AABBCCDDEEFF0011AABBCCDDEEFF0011AABBCCDDEEFF0011"));
        handshakeLayer = new HandshakeLayer(context, recordLayer);
        context.setTlsState(TlsState.RETRY_HELLO);
        handshakeLayer.sendHelloRetryRequest();
        byte[] helloRetryBytes = outputStream.toByteArray();
        assertEquals("The retry request has an invalid length",93, helloRetryBytes.length); //See parser below for detailed information
        //Since we do not have a HelloRetryRequest parser we need to create one manually
        RecordParser parser = new RecordParser(helloRetryBytes);
        Record parsedRecord = parser.parse();
        Assert.assertEquals("The record parser must parse the first 5 bytes",88, parsedRecord.getData().length);
        Assert.assertArrayEquals("The TLS version must be 1.2",Util.hexStringToByteArray("0303"), parsedRecord.getVersion());
        Assert.assertEquals("The protocoll type must be handshake",ProtocolType.HANDSHAKE.getByteValue(), parsedRecord.getType());
        Parser tempParser = new Parser(parsedRecord.getData()) {
            @Override
            public Object parse() {
                assertEquals("Handshake Type must be 2",2, parseByteField()); //type
                assertEquals("Data must be 84 bytes long",0x54, parseIntField(3)); //length
                Assert.assertArrayEquals("Protocol version must be TLS1.2",ProtocolVersion.TLS_1_2.getValue(), parseByteArrayField(2)); //version
                Assert.assertArrayEquals("The random must be the SHA256 of 'HelloRetryRequest'",Util.hexStringToByteArray("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"),parseByteArrayField(32)); //
                assertEquals("The session id must be 32 bytes long",32, parseByteField()); //session id length
                Assert.assertArrayEquals("The client sessionId is in the context",Util.hexStringToByteArray("AABBCCDDEEFF0011AABBCCDDEEFF0011AABBCCDDEEFF0011AABBCCDDEEFF0011"), parseByteArrayField(32)); //sessionID
                Assert.assertArrayEquals("The Cipher Suite must be supported by the server and the client",CipherSuite.TLS_AES_128_GCM_SHA256.getValue(), parseByteArrayField(2)); //ciphersuite
                Assert.assertArrayEquals("We do not use compression",new byte[]{0x00}, parseByteArrayField(1)); //compression
                assertEquals("We should have 12 Bytes with extensions here", 0x000c, parseIntField(2)); //Extensions
                //we do not parse extension bytes - since they re somewhat random / random order
                assertEquals(12, getBytesLeft());
                return null;
            }
        };
        tempParser.parse();
        assertEquals("The version must be set in the context",ProtocolVersion.TLS_1_3, context.getSelectedVersion()); //This should be true since we only support TLS 1.3
        assertNull("This cannot be set before the client's response",context.getSelectedCiphersuite()); //Ciphersuite should not be negotiated before we received the second CH
    }

    @Test
    @Category(de.rub.nds.praktikum.Aufgabe4.class)
    public void testSendCertificates() {
        handshakeLayer = new HandshakeLayer(context, recordLayer);
        context.setCertificateChain(Certificate.EMPTY_CHAIN);
        handshakeLayer.sendCertificates();
        byte[] certificateBytes = outputStream.toByteArray();
        assertEquals(13, certificateBytes.length);//We send an empty encryptedExtension message in a single record
        RecordParser parser = new RecordParser(certificateBytes);
        Record parsedRecord = parser.parse();
        Assert.assertEquals(8, parsedRecord.getData().length);
        Assert.assertArrayEquals("Record Version must be TLS1.2",Util.hexStringToByteArray("0303"), parsedRecord.getVersion());
        Assert.assertEquals("This is a handshake message",ProtocolType.HANDSHAKE.getByteValue(), parsedRecord.getType());
        Parser tempParser = new Parser(parsedRecord.getData()) {
            @Override
            public Object parse() {
                // 1ByteHandshakeMessageType + 3 ByteHandskaeMessageLen + 1 Zero Byte + 3 Byte CertListLen
                Assert.assertArrayEquals(Util.hexStringToByteArray("0b00000400000000"), parseByteArrayField(8));
                return null;
            }
        };
        tempParser.parse();
        assertArrayEquals("The Digest does not equal - did you foret to update it?", Util.hexStringToByteArray("e029dfef0f302e074cf6da852a57ce138a1b09b7f9572ac91772761230aa2bb3"), context.getDigest());
    }

    @Test
    @Category(de.rub.nds.praktikum.Aufgabe4.class)
    public void testSendCertificateVerify() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        when(context.getSecureRandom()).thenReturn(new NotSecureRandom((byte) 0x01));
        handshakeLayer = new HandshakeLayer(context, recordLayer);
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secp256r1");
        KeyPair pair = null;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        keyPairGenerator.initialize(ecGenSpec, new TestRandomData(Util.hexStringToByteArray("c1a0d20c70a2fdfbd45553db21ce66c3aa1a53c082c92e1bfb178360b8723ed4")));
        pair = keyPairGenerator.generateKeyPair();
        context.setCertificatePrivateKey(pair.getPrivate());
        context.setSelectedSignatureAndHashAlgorithm(SignatureAndHashAlgorithm.ECDSA_SHA256);
        final PublicKey pubKey = pair.getPublic();
        handshakeLayer.sendCertificateVerify();
        byte[] certificateVerifyBytes = outputStream.toByteArray();
        RecordParser parser = new RecordParser(certificateVerifyBytes);
        Record parsedRecord = parser.parse();
        Assert.assertArrayEquals("Record Version must be TLS1.2",Util.hexStringToByteArray("0303"), parsedRecord.getVersion());
        Assert.assertEquals("Record type must be handshake",ProtocolType.HANDSHAKE.getByteValue(), parsedRecord.getType());
        Parser tempParser = new Parser(parsedRecord.getData()) {
            @Override
            public Object parse() {
                Assert.assertArrayEquals("Handshake message type must be certificate verify",Util.hexStringToByteArray("0f"), parseByteArrayField(1));
                int hsLength = parseIntField(3); //The length is somewhat random dependent
                Assert.assertArrayEquals("The shignature and hask algorithm is not ECDSA_SHA256",SignatureAndHashAlgorithm.ECDSA_SHA256.getValue(), parseByteArrayField(2));
                int signatureLength = parseIntField(2);
                byte[] signature = parseByteArrayField(signatureLength);

                assertEquals("The the message len or the signature len is invalid",signatureLength, hsLength - 4);
                assertArrayEquals("Signature is not correct", Util.hexStringToByteArray("304402206ff03b949241ce1dadd43519e6960e0a85b41a69a05c328103aa2bce1594ca1602207104e010131c71c9c867de6b504880b6209a0ab3e1df0eef9f8c1b5747a26211"), signature);
                return null;
            }
        };
        tempParser.parse();
        assertArrayEquals("The Digest does not equal - did you foret to update it?", Util.hexStringToByteArray("0d37207506cfef0db632d5e962dc2da5c0901cfc6e5aba2f5392b84ff6bd77fb"), context.getDigest());
    }

    @Test
    @Category(de.rub.nds.praktikum.Aufgabe4.class)
    public void testSendFinished() {
        context.setHandshakeSecret(Util.hexStringToByteArray("00111222"));
        context.setSharedEcdheSecret(Util.hexStringToByteArray("CCDDEEFF"));
        context.setServerHandshakeTrafficSecret(Util.hexStringToByteArray("FFDDEEAABBCC"));
        context.setClientHandshakeTrafficSecret(Util.hexStringToByteArray("0123456789"));
        handshakeLayer = new HandshakeLayer(context, recordLayer);
        handshakeLayer.sendFinished();
        byte[] finishedBytes = outputStream.toByteArray();
        assertEquals(41, finishedBytes.length);//We send an empty encryptedExtension message in a single record
        RecordParser parser = new RecordParser(finishedBytes);
        Record parsedRecord = parser.parse();
        Assert.assertEquals(36, parsedRecord.getData().length);
        Assert.assertArrayEquals("Record version must be TLS1.2",Util.hexStringToByteArray("0303"), parsedRecord.getVersion());
        Assert.assertEquals("Record type must be handshake",ProtocolType.HANDSHAKE.getByteValue(), parsedRecord.getType());
        Parser tempParser = new Parser(parsedRecord.getData()) {
            @Override
            public Object parse() {
                Assert.assertArrayEquals("Handshake message type must be finished",Util.hexStringToByteArray("14"), parseByteArrayField(1)); //Type
                Assert.assertArrayEquals("HMAC must be 32 bytes long",Util.hexStringToByteArray("000020"), parseByteArrayField(3)); //Length
                Assert.assertArrayEquals("HMAC is invalid. Did you update the context digest?",Util.hexStringToByteArray("671483aa33b201e6e099928561b160048d85cb7d8419bad34c84e57cd10e8d9e"), parseByteArrayField(32)); //verify Data
                return null;
            }
        };
        assertNotNull("Client finshed key must be set", context.getClientFinishedKey());
        assertNotNull("Server finshed key must be set", context.getServerFinishedKey());
        assertArrayEquals("The Digest does not equal - did you foret to update it?", Util.hexStringToByteArray("9ab9f32be1080f7f1ba315137e4f38c25e216dc33185b386d92c234a8c9a441b"), context.getDigest());
        tempParser.parse();
    }

    @Test
    @Category(de.rub.nds.praktikum.Aufgabe2.class)
    public void testProcessByteClientHello() {
        handshakeLayer = new HandshakeLayer(context, recordLayer);
        handshakeLayer.processByteStream(Util.hexStringToByteArray("0100012e0303d2070dda5da15b5b1e8df24392f06794436f684f4cde088fd852d7c0b6fdff4c20781bf656122613ab8dfdea009961ebe4bcacc71f1f5547c8a2f753273f2f68ad003e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff010000a70000000e000c0000096c6f63616c686f7374000b000403000102000a000c000a001d0017001e00190018002300000016000000170000000d0030002e040305030603080708080809080a080b080408050806040105010601030302030301020103020202040205020602002b0009080304030303020301002d00020101003300260024001d0020c7ba2d3c2543a66a3e1575dab429f61d3a0d6e680c83e86608330079d9c00b1c"));
        assertEquals("The state must be recieved client helllo",TlsState.RECVD_CH, context.getTlsState());
        assertArrayEquals("the client random must be set in the context",Util.hexStringToByteArray("d2070dda5da15b5b1e8df24392f06794436f684f4cde088fd852d7c0b6fdff4c"), context.getClientRandom());
        assertArrayEquals("the client session id must be set in the context",Util.hexStringToByteArray("781bf656122613ab8dfdea009961ebe4bcacc71f1f5547c8a2f753273f2f68ad"), context.getClientSessionId());
        assertEquals("We have only one compression method",1, context.getClientSupportedCompressionMethods().size());
        assertEquals("The compression method must be zero",CompressionMethod.NULL, context.getClientSupportedCompressionMethods().get(0));
        assertEquals("The list must contain 31 cipher suites",31, context.getClientCipherSuiteList().size()); //The list contains only 3 tls.1.3 suites - the rest will be null since we cannot convert them
        assertEquals("The list must contain 5 named goups",5, context.getClientNamedGroupList().size());
        assertEquals("The list must contain 4 TLS versions ",4, context.getClientSupportedVersions().size());
        assertEquals("The list must contain 1 key share",1, context.getClientKeyShareEntryList().size());
    }

    @Test
    @Category(de.rub.nds.praktikum.Aufgabe3.class)
    public void testProcessByteClientHelloWithCrypto() {
        testProcessByteClientHello();
        assertArrayEquals("The Digest does not equal - did you foret to update it?", Util.hexStringToByteArray("5e9eefc1aad078b8645affc5a343322dc8f50a9438185cf776e7073edd4e6a9e"), context.getDigest());
    }

    @Test(expected = UnexpectedMessageException.class)
    @Category(de.rub.nds.praktikum.Aufgabe2.class)
    public void testProcessClientHelloWrongState1() {
        context.setTlsState(TlsState.CONNECTED);
        handshakeLayer = new HandshakeLayer(context, recordLayer);
        handshakeLayer.processByteStream(Util.hexStringToByteArray("0100012e0303d2070dda5da15b5b1e8df24392f06794436f684f4cde088fd852d7c0b6fdff4c20781bf656122613ab8dfdea009961ebe4bcacc71f1f5547c8a2f753273f2f68ad003e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff010000a70000000e000c0000096c6f63616c686f7374000b000403000102000a000c000a001d0017001e00190018002300000016000000170000000d0030002e040305030603080708080809080a080b080408050806040105010601030302030301020103020202040205020602002b0009080304030303020301002d00020101003300260024001d0020c7ba2d3c2543a66a3e1575dab429f61d3a0d6e680c83e86608330079d9c00b1c"));
    }

    @Test(expected = UnexpectedMessageException.class)
    @Category(de.rub.nds.praktikum.Aufgabe2.class)
    public void testProcessClientHelloWrongState2() {
        context.setTlsState(TlsState.ERROR);
        handshakeLayer = new HandshakeLayer(context, recordLayer);
        handshakeLayer.processByteStream(Util.hexStringToByteArray("0100012e0303d2070dda5da15b5b1e8df24392f06794436f684f4cde088fd852d7c0b6fdff4c20781bf656122613ab8dfdea009961ebe4bcacc71f1f5547c8a2f753273f2f68ad003e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff010000a70000000e000c0000096c6f63616c686f7374000b000403000102000a000c000a001d0017001e00190018002300000016000000170000000d0030002e040305030603080708080809080a080b080408050806040105010601030302030301020103020202040205020602002b0009080304030303020301002d00020101003300260024001d0020c7ba2d3c2543a66a3e1575dab429f61d3a0d6e680c83e86608330079d9c00b1c"));
    }

    @Test(expected = UnexpectedMessageException.class)
    @Category(de.rub.nds.praktikum.Aufgabe2.class)
    public void testProcessClientHelloWrongState3() {
        context.setTlsState(TlsState.NEGOTIATED);
        handshakeLayer = new HandshakeLayer(context, recordLayer);
        handshakeLayer.processByteStream(Util.hexStringToByteArray("0100012e0303d2070dda5da15b5b1e8df24392f06794436f684f4cde088fd852d7c0b6fdff4c20781bf656122613ab8dfdea009961ebe4bcacc71f1f5547c8a2f753273f2f68ad003e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff010000a70000000e000c0000096c6f63616c686f7374000b000403000102000a000c000a001d0017001e00190018002300000016000000170000000d0030002e040305030603080708080809080a080b080408050806040105010601030302030301020103020202040205020602002b0009080304030303020301002d00020101003300260024001d0020c7ba2d3c2543a66a3e1575dab429f61d3a0d6e680c83e86608330079d9c00b1c"));
    }

    @Test(expected = UnexpectedMessageException.class)
    @Category(de.rub.nds.praktikum.Aufgabe2.class)
    public void testProcessClientHelloWrongState4() {
        context.setTlsState(TlsState.RECVD_CH);
        handshakeLayer = new HandshakeLayer(context, recordLayer);
        handshakeLayer.processByteStream(Util.hexStringToByteArray("0100012e0303d2070dda5da15b5b1e8df24392f06794436f684f4cde088fd852d7c0b6fdff4c20781bf656122613ab8dfdea009961ebe4bcacc71f1f5547c8a2f753273f2f68ad003e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff010000a70000000e000c0000096c6f63616c686f7374000b000403000102000a000c000a001d0017001e00190018002300000016000000170000000d0030002e040305030603080708080809080a080b080408050806040105010601030302030301020103020202040205020602002b0009080304030303020301002d00020101003300260024001d0020c7ba2d3c2543a66a3e1575dab429f61d3a0d6e680c83e86608330079d9c00b1c"));
    }

    @Test(expected = UnexpectedMessageException.class)
    @Category(de.rub.nds.praktikum.Aufgabe2.class)
    public void testProcessClientHelloWrongState5() {
        context.setTlsState(TlsState.WAIT_FINISHED);
        handshakeLayer = new HandshakeLayer(context, recordLayer);
        handshakeLayer.processByteStream(Util.hexStringToByteArray("0100012e0303d2070dda5da15b5b1e8df24392f06794436f684f4cde088fd852d7c0b6fdff4c20781bf656122613ab8dfdea009961ebe4bcacc71f1f5547c8a2f753273f2f68ad003e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff010000a70000000e000c0000096c6f63616c686f7374000b000403000102000a000c000a001d0017001e00190018002300000016000000170000000d0030002e040305030603080708080809080a080b080408050806040105010601030302030301020103020202040205020602002b0009080304030303020301002d00020101003300260024001d0020c7ba2d3c2543a66a3e1575dab429f61d3a0d6e680c83e86608330079d9c00b1c"));
    }

    @Test
    @Category(de.rub.nds.praktikum.Aufgabe4.class)
    public void testProcessByteFinished() {
        context.setClientHandshakeTrafficSecret(Util.hexStringToByteArray("c677a34f169db51f85411ddcacb9c461b603f72923d2a00dc918a915052e37a8"));
        context.setServerHandshakeTrafficSecret(Util.hexStringToByteArray("a0b47ba9e740d01c1da4960a174d79d03e71d178d18afa5f77a45cdcad3bff03"));
        context.setClientApplicationTrafficSecret(Util.hexStringToByteArray("0011"));
        context.setServerApplicationTrafficSecret(Util.hexStringToByteArray("2211"));

        KeyGenerator.adjustFinishedKeys(context);
        handshakeLayer = new HandshakeLayer(context, recordLayer);
        context.setTlsState(TlsState.WAIT_FINISHED);
        handshakeLayer.processByteStream(Util.hexStringToByteArray("140000203ec350bc78c95325caf5547ac4c4753b276ec2ae49dc0953173864cd7414a9df"));
        assertEquals("The state must be connected",TlsState.CONNECTED, context.getTlsState());
        assertArrayEquals("The Digest does not equal - did you foret to update it?", Util.hexStringToByteArray("898fd7e90bf515ecb8ab6da1f7aa37d4737ed837bdeabfaaecc939809ad06c86"), context.getDigest());
    }

    @Test(expected = TlsException.class)
    @Category(de.rub.nds.praktikum.Aufgabe4.class)
    public void testProcessByteInvalidFinished() {
        context.setClientHandshakeTrafficSecret(Util.hexStringToByteArray("c677a34f169db51f85411ddcacb9c461b603f72923d2a00dc918a915052e37a8"));
        context.setServerHandshakeTrafficSecret(Util.hexStringToByteArray("a0b47ba9e740d01c1da4960a174d79d03e71d178d18afa5f77a45cdcad3bff03"));
        KeyGenerator.adjustFinishedKeys(context);
        handshakeLayer = new HandshakeLayer(context, recordLayer);
        context.setTlsState(TlsState.WAIT_FINISHED);
        handshakeLayer.processByteStream(Util.hexStringToByteArray("140000203ec350bc78c95325caf5547ac4c4753FF76ec2ae49dc0953173864cd7414a9df"));
    }
}
