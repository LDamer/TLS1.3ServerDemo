package de.rub.nds.praktikum.messages;

import de.rub.nds.praktikum.constants.FieldLength;
import de.rub.nds.praktikum.exception.TlsException;
import de.rub.nds.praktikum.messages.certificate.CertificateEntry;
import de.rub.nds.praktikum.messages.certificate.CertificateEntrySerializer;
import de.rub.nds.praktikum.util.Util;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;

/**
 * A serializer class which transforms a certificate message object into its
 * byte representation
 */
public class CertificateMessageSerializer extends Serializer<CertificateMessage> {

    private final CertificateMessage message;

    /**
     * Constructor
     *
     * @param message message that should be serialized
     */
    public CertificateMessageSerializer(CertificateMessage message) {
        this.message = message;
    }

    @Override
    protected void serializeBytes() {
        //throw new UnsupportedOperationException("Add code here");
        appendByte((byte)0x00); // certificate request context length
        ArrayList<byte[]> serializedCertificateEntries = new ArrayList<>();
        int len = 0;
        for(CertificateEntry ce : message.getCertificateEntryList()){
            CertificateEntrySerializer se = new CertificateEntrySerializer(ce);
            byte[] data = se.serialize();
            serializedCertificateEntries.add(data);
            len += data.length;
        }
        appendBytes(Util.convertIntToBytes(len, 3));
        for(byte[] data : serializedCertificateEntries){
            appendBytes(data);
        }


    }

}
