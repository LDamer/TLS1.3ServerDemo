package de.rub.nds.praktikum.messages.certificate;

import de.rub.nds.praktikum.constants.FieldLength;
import de.rub.nds.praktikum.exception.TlsException;
import de.rub.nds.praktikum.messages.Serializer;
import de.rub.nds.praktikum.messages.extensions.Extension;
import de.rub.nds.praktikum.util.Util;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * A serializer for a certificate entry
 */
public class CertificateEntrySerializer extends Serializer<CertificateEntry> {

    private final CertificateEntry certificateEntry;

    /**
     * Constructor
     *
     * @param certificateEntry The certificate Entry that should get serialized
     */
    public CertificateEntrySerializer(CertificateEntry certificateEntry) {
        this.certificateEntry = certificateEntry;
    }

    @Override
    protected void serializeBytes() {
        //throw new UnsupportedOperationException("Add code here");
        try{
            byte[] certBytes = certificateEntry.getCertificate().getEncoded();
            byte[] len = Util.convertIntToBytes(certBytes.length, 3);
            byte[] extensionLength = new byte[]{(byte)0x00,(byte)0x00}; // no extension lists

            appendBytes(len);
            appendBytes(certBytes);
            appendBytes(extensionLength);

        } catch (IOException e){
            throw new TlsException("cannot encode certificate");
        }
    }

}
