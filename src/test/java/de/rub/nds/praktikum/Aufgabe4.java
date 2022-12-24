package de.rub.nds.praktikum;

import de.rub.nds.praktikum.constants.CipherSuite;
import de.rub.nds.praktikum.constants.ProtocolVersion;
import de.rub.nds.praktikum.messages.Finished;
import de.rub.nds.praktikum.messages.FinishedParser;
import de.rub.nds.praktikum.messages.FinishedSerializer;
import de.rub.nds.praktikum.protocol.RecordLayer;
import de.rub.nds.praktikum.protocol.SessionContext;
import de.rub.nds.praktikum.records.RecordParser;
import de.rub.nds.praktikum.records.RecordSerializer;
import de.rub.nds.praktikum.util.Util;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
import de.rub.nds.praktikum.records.Record;
import static org.junit.Assert.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Security;

public class Aufgabe4 {

    private RecordLayer recordLayer;

    private ByteArrayOutputStream outputStream;

    private ByteArrayInputStream inputStream;

    @Before
    public void setUp() {
        Security.addProvider(new BouncyCastleProvider());
        outputStream = new ByteArrayOutputStream();

    }

    @Test
    public void testDecryptFinishedMessage(){
                                                                                //header  |
        //RecordParser parser  = new RecordParser(Util.hexStringToByteArray("170303003558b39ec23d18d9baec7b41f4e651146f5fc341fe893379318e973d777fe27f9aade50a2b0da7fd22646490e0d0df3f9d7c703151b8"));
        RecordParser parser  = new RecordParser(Util.hexStringToByteArray("17030300355cad612570a69858dc47bd2272ba0ed7ad4313871b21bb4170b442914eb8cd0fdc3df84131ebec03701ca18b1a51a669c4fbf6a1cd"));

        Record finishedRecordFromWireshark = parser.parse();

        SessionContext context = new SessionContext(null, null);
        //context.setClientWriteKey(Util.hexStringToByteArray("0f9e750587f043e1cd91046bfef1cb6c"));
        context.setClientWriteKey(Util.hexStringToByteArray("f6ae23ce44556119b1f465b68e52a15b"));
        context.setClientFinishedKey(Util.hexStringToByteArray("f6ae23ce44556119b1f465b68e52a15b"));
        //context.setClientWriteIv(Util.hexStringToByteArray("8903d210bc1bb2a82460dc7a"));
        context.setClientWriteIv(Util.hexStringToByteArray("a48667dfee3db23b08a4d04a"));


        context.setSelectedVersion(ProtocolVersion.TLS_1_3);
        context.setSelectedCiphersuite(CipherSuite.TLS_AES_128_GCM_SHA256);

        inputStream = new ByteArrayInputStream(new byte[0]);
        recordLayer = new RecordLayer(outputStream, inputStream, context, 0);
        recordLayer.activateEncryption();
        recordLayer.resetSequencenumbers();

        recordLayer.decrypt(finishedRecordFromWireshark);

        FinishedParser p = new FinishedParser(finishedRecordFromWireshark.getData());
        Finished f = p.parse();

        FinishedSerializer s = new FinishedSerializer(f);
        assertEquals("14000020c8f99248f87eab2680f39e1e6a8e310b022b95029e920005d773fb716a1bffda", Util.bytesToHexString(s.serialize()));
    }

}
