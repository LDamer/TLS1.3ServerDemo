package de.rub.nds.praktikum.messages.extensions;

import de.rub.nds.praktikum.constants.FieldLength;
import de.rub.nds.praktikum.constants.NamedGroup;
import de.rub.nds.praktikum.constants.SignatureAndHashAlgorithm;
import de.rub.nds.praktikum.exception.ParserException;
import de.rub.nds.praktikum.messages.Parser;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * A parser for the supported signatures and hash algorithms extension
 */
public class SupportedSignaturesAlgorithmExtensionParser extends Parser<SupportedSignaturesAlgorithmExtension> {

    /**
     * Constructor
     *
     * @param array The byte[] that should be parsed
     */
    public SupportedSignaturesAlgorithmExtensionParser(byte[] array) {
        super(array);
    }

    @Override
    public SupportedSignaturesAlgorithmExtension parse() {
        //throw new UnsupportedOperationException("Add code here");
        int payloadLength = parseIntField(2);
        ArrayList<SignatureAndHashAlgorithm> algorithms = new ArrayList<>();
        for(int i = 0; i < payloadLength; i += 2){
            byte[] namedGroup = parseByteArrayField(2);
            SignatureAndHashAlgorithm g = SignatureAndHashAlgorithm.convert(namedGroup);
            algorithms.add(g);
        }
        if(getBytesLeft() != 0){
            throw new ParserException("bytesLeft != 0");
        }
        return new SupportedSignaturesAlgorithmExtension(algorithms);

    }

}
