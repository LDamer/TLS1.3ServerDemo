package de.rub.nds.praktikum.messages.extensions;

import de.rub.nds.praktikum.constants.ExtensionType;
import de.rub.nds.praktikum.constants.FieldLength;
import de.rub.nds.praktikum.constants.NamedGroup;
import de.rub.nds.praktikum.exception.ParserException;
import de.rub.nds.praktikum.messages.Parser;
import de.rub.nds.praktikum.util.Util;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * A parser class which parses a provided byte[] into a key share extension
 * object
 */
public class KeyShareExtensionParser extends Parser<KeyShareExtension> {

    /**
     * Constructor
     *
     * @param array the byte[] that should be parsed
     */
    public KeyShareExtensionParser(byte[] array) {
        super(array);
    }

    @Override
    public KeyShareExtension parse() {
        //throw new UnsupportedOperationException("Add code here");
        /*
        byte[] t = parseByteArrayField(FieldLength.EXTENSION_TYPE);
        ExtensionType type = ExtensionType.convert(t);
        if(type != ExtensionType.KEY_SHARE){
            throw new ParserException();
        }
        */
        int byte_seen = 0;
        int extension_len = parseIntField(FieldLength.EXTENSION_LENGTH);
        ArrayList<KeyShareEntry> shareList = new ArrayList<>();

        while(byte_seen < extension_len) {//iterate through whole extension
            //parse a single KeyShare

            //int keyShare_len = parseIntField(FieldLength.KEYSHARE_LIST_LENGTH);//len of group + share
            byte[] group_bytes = parseByteArrayField(FieldLength.NAMED_GROUPS_LENGTH);
            //NamedGroup g = NamedGroup.convert(group_bytes);
            int pubKey_len = parseIntField(FieldLength.KEYSHARE_LENGTH);
            byte[] pubKey = parseByteArrayField(pubKey_len);

            KeyShareEntry entry = new KeyShareEntry(group_bytes, pubKey);
            shareList.add(entry);
            byte_seen += group_bytes.length + pubKey.length + FieldLength.KEYSHARE_LENGTH;
        }
        if(getBytesLeft() != 0 || extension_len != byte_seen){
            throw new ParserException("still bytes left! wrong Length field");
        }
        KeyShareExtension ext = new KeyShareExtension(shareList);
        return ext;
    }
}
