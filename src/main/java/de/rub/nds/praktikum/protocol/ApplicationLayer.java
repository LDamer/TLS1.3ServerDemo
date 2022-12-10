package de.rub.nds.praktikum.protocol;

import de.rub.nds.praktikum.constants.ProtocolType;
import de.rub.nds.praktikum.constants.TlsState;
import de.rub.nds.praktikum.exception.TlsException;
import de.rub.nds.praktikum.records.Record;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * The application layer is responsible for the exchange of application data
 */
public class ApplicationLayer extends TlsSubProtocol {

    private final SessionContext context;

    private final RecordLayer recordLayer;

    private ByteArrayOutputStream appDataBuffer;

    /**
     * Constructor
     *
     * @param context     The SessionContext for which this application layer should
     *                    be constructed
     * @param recordLayer The record layer that should be used by this
     *                    application layer
     */
    public ApplicationLayer(SessionContext context, RecordLayer recordLayer) {
        super(ProtocolType.APPLICATION_DATA.getByteValue());
        this.context = context;
        this.recordLayer = recordLayer;
        appDataBuffer = new ByteArrayOutputStream();
    }

    /**
     * Sends the data[] as application data to the peer
     *
     * @param data the data[] to send
     * @throws IOException if something goes wrong during transmission
     */
    public void sendData(byte[] data) throws IOException {
        //throw new UnsupportedOperationException("Add code here");
        recordLayer.sendData(data, ProtocolType.APPLICATION_DATA);
    }

    /**
     * If the Handshake is successfully finished and we receive actual app data
     * return its content.
     *
     * @param r The received record
     * @return The application data content of the record
     */
    public byte[] receiveData(Record r) {
        //throw new UnsupportedOperationException("Add code here");
        return r.getData();
    }

    /**
     * Passes data to the appDataBuffer such that the application can fetch it.
     *
     * @param stream
     */
    @Override
    public void processByteStream(byte[] stream) {
        //throw new UnsupportedOperationException("Add code here");
        try {
            appDataBuffer.write(stream);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * @return
     */
    public byte[] fetchAppData() {
        //throw new UnsupportedOperationException("Add code here");
        return this.appDataBuffer.toByteArray();

    }

}
