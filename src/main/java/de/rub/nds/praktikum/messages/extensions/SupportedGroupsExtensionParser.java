package de.rub.nds.praktikum.messages.extensions;

import de.rub.nds.praktikum.constants.FieldLength;
import de.rub.nds.praktikum.constants.NamedGroup;
import de.rub.nds.praktikum.exception.ParserException;
import de.rub.nds.praktikum.messages.Parser;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * A parser for the supported groups extension
 */
public class SupportedGroupsExtensionParser extends Parser<SupportedGroupsExtension> {

    /**
     * Constructor
     *
     * @param array the byte[] that should be parsed
     */
    public SupportedGroupsExtensionParser(byte[] array) {
        super(array);
    }

    @Override
    public SupportedGroupsExtension parse() {
        //throw new UnsupportedOperationException("Add code here");
        int payloadLength = parseIntField(2);
        ArrayList<NamedGroup> groups = new ArrayList<>();
        for(int i = 0; i < payloadLength; i += 2){
            byte[] namedGroup = parseByteArrayField(2);
            NamedGroup g = NamedGroup.convert(namedGroup);
            groups.add(g);
        }
        if(getBytesLeft() != 0){
            throw new ParserException("bytesLeft != 0");
        }
        return new SupportedGroupsExtension(groups);
    }

}
