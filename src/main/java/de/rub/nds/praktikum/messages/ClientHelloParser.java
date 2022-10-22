package de.rub.nds.praktikum.messages;

import de.rub.nds.praktikum.constants.*;
import de.rub.nds.praktikum.exception.ParserException;
import de.rub.nds.praktikum.messages.extensions.Extension;
import de.rub.nds.praktikum.messages.extensions.KeyShareExtension;
import de.rub.nds.praktikum.messages.extensions.KeyShareExtensionParser;
import de.rub.nds.praktikum.messages.extensions.SupportedGroupsExtension;
import de.rub.nds.praktikum.messages.extensions.SupportedGroupsExtensionParser;
import de.rub.nds.praktikum.messages.extensions.SupportedSignaturesAlgorithmExtension;
import de.rub.nds.praktikum.messages.extensions.SupportedSignaturesAlgorithmExtensionParser;
import de.rub.nds.praktikum.messages.extensions.SupportedVersionsExtension;
import de.rub.nds.praktikum.messages.extensions.SupportedVersionsExtensionParser;
import de.rub.nds.praktikum.util.Util;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.net.ProtocolFamily;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * A parser class which parses a provided byte[] into a client hello object
 */
public class ClientHelloParser extends Parser<ClientHello> {

    private byte[] version;
    private byte[] random;
    private byte[] sessionId;
    private byte[] cipherSuites;
    private byte[] compressionMethods;
    private byte[] extensionBytes;

    /**
     * Constructor
     *
     * @param array byte[] that should be parsed
     */
    public ClientHelloParser(byte[] array) {
        super(array);
    }

    @Override
    public ClientHello parse() {
        //should work!

        //parse handshakeType

        /* In handshake layer, not here!
        HandshakeMessageType handshake_type;
        if(parseByteField() == HandshakeMessageType.CLIENT_HELLO.getValue()){
            handshake_type = HandshakeMessageType.CLIENT_HELLO;
        }else{
            throw new ParserException("ClientHelloParser: this is not a ClientHello message[wrong mesage type byte]");
        }

        //parse length
        int lenOfHandshake = parseIntField(FieldLength.HANDSHAKE_LENGTH);
        */

        //parse version
        ProtocolVersion version_in_header = ProtocolVersion.convert(parseByteArrayField(FieldLength.VERSION));
        //parse ClientRandom
        byte[] clientRandom = parseByteArrayField(FieldLength.RANDOM);
        //parse useless session ID. Deprecated in TLS 1.3
        int sessionID_len = parseIntField(FieldLength.SESSION_ID_LENGTH);
        byte[] sessionID_fake = parseByteArrayField(sessionID_len);
        //parse CipherSuites
        int cipherSuitesLen = parseIntField(FieldLength.CIPHER_SUITE_LENGTH);
        ArrayList<CipherSuite> cipherList = new ArrayList<>();
        for(int i = 0; i < cipherSuitesLen; i+=2){
            cipherList.add(CipherSuite.convert(parseByteArrayField(2)));
        }

        //parse compression. No compression in TLS 1.3
        int compressionMethodsLen = parseIntField(1);
        int compressionMethod = parseIntField(1);
        ArrayList<CompressionMethod> compressionList = new ArrayList<>();
        compressionList.add(CompressionMethod.NULL);
        if(compressionMethodsLen != 1 || compressionMethod != 0){
            throw new ParserException("ClientHelloParser: compression must be a null byte!");
        }

        //parse ExtensionLen
        int lenOfAllExtension = parseIntField(FieldLength.EXTENSIONS_LENGTH);
        //parse extensions
        ArrayList<Extension> extensionsList = new ArrayList<>();
        int seenBytes = 0;
        while(seenBytes < lenOfAllExtension){
            int headerLenOfExtension = FieldLength.EXTENSION_LENGTH+FieldLength.EXTENSION_TYPE;

            ExtensionType type = ExtensionType.convert(parseByteArrayField(FieldLength.EXTENSION_TYPE));
            int lenOfThisExtension = parseIntField(FieldLength.EXTENSION_LENGTH);
            setPointer(getPointer()-headerLenOfExtension);// set pointer back to start of extension
            if(type == ExtensionType.KEY_SHARE){
                KeyShareExtensionParser parser = new KeyShareExtensionParser(parseByteArrayField(lenOfThisExtension + headerLenOfExtension));
                KeyShareExtension share = parser.parse();
                extensionsList.add(share);
            }else if(type == ExtensionType.SUPPORTED_VERSIONS){
                SupportedVersionsExtensionParser parser = new SupportedVersionsExtensionParser(parseByteArrayField(lenOfThisExtension + headerLenOfExtension));
                SupportedVersionsExtension sv = parser.parse();
                extensionsList.add(sv);
            }else if(type == ExtensionType.SUPPORTED_GROUPS){
                SupportedGroupsExtensionParser parser = new SupportedGroupsExtensionParser(parseByteArrayField(lenOfThisExtension + headerLenOfExtension));
                SupportedGroupsExtension e = parser.parse();
                extensionsList.add(e);
            }else if(type == ExtensionType.SUPPORTED_SIGNATURES){
                SupportedSignaturesAlgorithmExtensionParser parser = new SupportedSignaturesAlgorithmExtensionParser(parseByteArrayField(lenOfThisExtension + headerLenOfExtension));
                SupportedSignaturesAlgorithmExtension e = parser.parse();
                extensionsList.add(e);
            }else{
                //just dismiss the bytes
                parseArrayOrTillEnd(lenOfThisExtension + headerLenOfExtension);
            }
            seenBytes += lenOfThisExtension + headerLenOfExtension;// +2 for type +2 for len fields
        }
        ClientHello ch = new ClientHello(version_in_header,clientRandom,sessionID_fake, cipherList, compressionList, extensionsList);
        return ch;
    }

}
