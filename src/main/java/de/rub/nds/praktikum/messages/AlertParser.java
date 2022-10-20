package de.rub.nds.praktikum.messages;

import de.rub.nds.praktikum.exception.ParserException;

/**
 * A parser class for alert messages
 */
public class AlertParser extends Parser<Alert> {

    /**
     * Constructor for the parser
     *
     * @param array The array that should be parsed
     */
    public AlertParser(byte[] array) {
        super(array);
    }

    @Override
    public Alert parse() {
        //throw new UnsupportedOperationException("Add code here");
        byte level = parseByteField();
        byte desc = parseByteField();
        return new Alert(level, desc);
    }

}
