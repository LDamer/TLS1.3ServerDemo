package de.rub.nds.praktikum.messages;

import de.rub.nds.praktikum.constants.ExtensionType;
import de.rub.nds.praktikum.exception.TlsException;
import de.rub.nds.praktikum.messages.extensions.Extension;
import de.rub.nds.praktikum.util.Util;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * A serializer class which transfroms a server hello message object into its
 * byte representation
 */
public class ServerHelloSerializer extends Serializer<ServerHello> {

    private final ServerHello hello;

    /**
     * Constructor
     *
     * @param hello The message to serialize
     */
    public ServerHelloSerializer(ServerHello hello) {
        this.hello = hello;
    }

    @Override
    protected void serializeBytes() {
        //throw new UnsupportedOperationException("Add code here");
        appendBytes(hello.getVersion().getValue());
        appendBytes(hello.getRandom());
        appendByte((byte)hello.getSessionId().length);
        appendBytes(hello.getSessionId());
        appendBytes(hello.getSelectedCiphersuite().getValue());
        appendBytes(hello.getSelectedCompressionMethod().getValue());

        int lenOfExtensions = 0;
        for(Extension e : hello.getExtensionList()){
            if(e.getType().equals(ExtensionType.KEY_SHARE)
                || e.getType().equals(ExtensionType.SUPPORTED_VERSIONS)){
                    lenOfExtensions += e.getSerializer().serialize().length;
                    lenOfExtensions += 2 + 2;//type + len
            }
        }
        appendInt(lenOfExtensions, 2);

        for(Extension e : hello.getExtensionList()){
            if(e.getType().equals(ExtensionType.SUPPORTED_VERSIONS)){
                appendBytes(e.getType().getValue());
                appendInt(e.getSerializer().serialize().length, 2);
                appendBytes(e.getSerializer().serialize());
                break;
            }
        }
        for(Extension e : hello.getExtensionList()){
            if(e.getType().equals(ExtensionType.KEY_SHARE)){
                appendBytes(e.getType().getValue());
                appendInt(e.getSerializer().serialize().length, 2);
                appendBytes(e.getSerializer().serialize());
                break;
            }
        }

    }
}
