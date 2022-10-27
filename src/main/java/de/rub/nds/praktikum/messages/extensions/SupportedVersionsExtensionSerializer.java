package de.rub.nds.praktikum.messages.extensions;

import de.rub.nds.praktikum.constants.ProtocolVersion;
import de.rub.nds.praktikum.exception.ParserException;
import de.rub.nds.praktikum.exception.SerializerException;
import de.rub.nds.praktikum.messages.Serializer;
import de.rub.nds.praktikum.util.Util;

/**
 * A serializer class which transforms a supported versions into its byte
 * representation
 */
public class SupportedVersionsExtensionSerializer extends Serializer<SupportedVersionsExtension> {

    private final SupportedVersionsExtension extension;

    /**
     * Constructor
     *
     * @param extension the extension that should be serialized
     */
    public SupportedVersionsExtensionSerializer(SupportedVersionsExtension extension) {
        this.extension = extension;
    }

    @Override
    protected void serializeBytes() {
        //throw new UnsupportedOperationException("Add code here");

        //appendBytes(extension.getType().getValue());

        //int lengthInHeader = extension.getSupportedVersions().size() * 2 + 1;
        //int lengthInPayload = lengthInHeader - 1;
        //appendInt((byte)lengthInHeader,2);
        //int verifyPayLoadLength = 0;
        for(ProtocolVersion p : extension.getSupportedVersions()){
            appendInt(Util.convertToInt(p.getValue()),2);
            //verifyPayLoadLength += 2;
        }
        //if(verifyPayLoadLength != lengthInPayload){
        //    throw new SerializerException();
        //}

    }

}
