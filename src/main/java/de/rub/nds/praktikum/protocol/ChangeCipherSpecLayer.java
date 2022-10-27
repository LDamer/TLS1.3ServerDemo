package de.rub.nds.praktikum.protocol;

import de.rub.nds.praktikum.constants.ProtocolType;
import de.rub.nds.praktikum.constants.ProtocolVersion;
import org.bouncycastle.crypto.tls.ChangeCipherSpec;

import java.io.IOException;

/**
 * The ChangeCipherSpecLayer is responsible for the transmission of dummy ccs
 * messages.
 *
 */
public class ChangeCipherSpecLayer extends TlsSubProtocol {

    private final SessionContext context;

    private final RecordLayer recordLayer;

    /**
     * Constructor
     *
     * @param context The SessionContext for which this CCS layer should be
     * constructed
     * @param recordLayer The record layer that should be used by this CCS layer
     */
    public ChangeCipherSpecLayer(SessionContext context, RecordLayer recordLayer) {
        super(ProtocolType.CHANGE_CIPHER_SPEC.getByteValue());
        this.context = context;
        this.recordLayer = recordLayer;

    }

    /**
     * Sends a dummy ChangeCipherSpec message, which only consists of the byte
     * 0x01. There is no extra class for this.
     *
     * @throws IOException If something goes wrong during transmission
     */
    public void sendCCS() throws IOException {
        //throw new UnsupportedOperationException("Add code here");
        recordLayer.sendData(new byte[]{(byte)0x01}, ProtocolType.CHANGE_CIPHER_SPEC);
    }

    /**
     * Parses the received ccs messages. We do nothing here and simply ignore
     * everything within.
     *
     * @param stream
     */
    @Override
    public void processByteStream(byte[] stream) {

    }
}
