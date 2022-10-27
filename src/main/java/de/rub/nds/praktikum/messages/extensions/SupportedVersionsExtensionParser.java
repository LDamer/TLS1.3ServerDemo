package de.rub.nds.praktikum.messages.extensions;

import de.rub.nds.praktikum.constants.ProtocolVersion;
import de.rub.nds.praktikum.constants.SignatureAndHashAlgorithm;
import de.rub.nds.praktikum.exception.ParserException;
import de.rub.nds.praktikum.messages.Parser;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * A parser class which parses a provided byte[] into a supported versions
 * extension object
 */
public class SupportedVersionsExtensionParser extends Parser<SupportedVersionsExtension> {

    /**
     * Constructor
     *
     * @param array a byte[] to parse
     */
    public SupportedVersionsExtensionParser(byte[] array) {
        super(array);
    }

    @Override
    public SupportedVersionsExtension parse() {
        //throw new UnsupportedOperationException("Add code here");
        int payloadLength = parseIntField(1);
        ArrayList<ProtocolVersion> versionsList = new ArrayList<>();
        for(int i = 0; i < payloadLength; i += 2){
            byte[] version = parseByteArrayField(2);
            ProtocolVersion v = ProtocolVersion.convert(version);
            versionsList.add(v);
        }
        if(getBytesLeft() != 0){
            throw new ParserException("bytesLeft != 0");
        }
        return new SupportedVersionsExtension(versionsList);
    }

}
