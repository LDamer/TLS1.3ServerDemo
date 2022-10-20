package de.rub.nds.praktikum.records;

import de.rub.nds.praktikum.constants.FieldLength;
import de.rub.nds.praktikum.messages.Parser;

/**
 * A parser class for tls records. This transforms a byte array into a record
 * object
 */
public class RecordParser extends Parser<Record> {

    /**
     * Constructor
     *
     * @param array The byte[] that should be parsed
     */
    public RecordParser(byte[] array) {
        super(array);
    }

    @Override
    public Record parse() {
        //throw new UnsupportedOperationException("Add code here");
        byte type;
        byte[] version, data;
        int length;

        type = parseByteField();
        version = parseByteArrayField(2);
        length = parseIntField(2);
        data = parseArrayOrTillEnd(length);
        return new Record(type, version, data);
    }
}
