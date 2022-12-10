package de.rub.nds.praktikum.messages;

import de.rub.nds.praktikum.constants.FieldLength;

/**
 * A serializer class which transforms a encrypted extension message object into
 * its byte representation
 */
public class EncryptedExtensionsSerializer extends Serializer<EncryptedExtensions> {

    private final EncryptedExtensions encryptedExtensions;

    /**
     * Constructor
     *
     * @param encryptedExtensions the encrypted extensions message that should
     *                            be serialized
     */
    public EncryptedExtensionsSerializer(EncryptedExtensions encryptedExtensions) {
        this.encryptedExtensions = encryptedExtensions;
    }

    @Override
    protected void serializeBytes() {
        //throw new UnsupportedOperationException("Add code here");
        appendBytes(new byte[]{(byte)0x00, (byte)0x00}); //length
        // no data
    }

}
