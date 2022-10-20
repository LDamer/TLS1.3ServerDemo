package de.rub.nds.praktikum.protocol;

import de.rub.nds.praktikum.constants.AlertDescription;
import de.rub.nds.praktikum.constants.AlertLevel;
import de.rub.nds.praktikum.constants.ProtocolType;
import de.rub.nds.praktikum.constants.TlsState;
import de.rub.nds.praktikum.messages.Alert;
import de.rub.nds.praktikum.messages.AlertParser;
import de.rub.nds.praktikum.messages.AlertSerializer;
import java.io.IOException;

/**
 * The alert layer is responsible for the exchange of error messages between the
 * client and the server.
 */
public class AlertLayer extends TlsSubProtocol {

    private final SessionContext context;

    private final RecordLayer recordLayer;

    /**
     * Constructor
     *
     * @param context     The SessionContext for which this alert layer should be
     *                    constructed
     * @param recordLayer The record layer that should be used by this alert
     *                    layer
     */
    public AlertLayer(SessionContext context, RecordLayer recordLayer) {
        super(ProtocolType.ALERT.getByteValue());
        this.context = context;
        this.recordLayer = recordLayer;

    }

    /**
     * Sends an alert message with the provided parameters and sets the tls
     * state in the context to error if the alert is fatal.
     *
     * @param alertLevel       level of the alert
     * @param alertDescription description of the alert
     * @throws IOException If something goes wrong during transmission
     */
    public void sendAlert(AlertLevel alertLevel, AlertDescription alertDescription) throws IOException {
        //throw new UnsupportedOperationException("Add code here");
        Alert alert = new Alert(alertLevel, alertDescription);
        if(alertLevel == AlertLevel.FATAL){
            context.setTlsState(TlsState.ERROR);
        }
        AlertSerializer serializer = new AlertSerializer(alert);
        recordLayer.sendData(serializer.serialize(), ProtocolType.ALERT);
    }

    /**
     * Parses the received alert messages. If a fatal alert is received the
     * TlsState is set to ERROR in the context.
     *
     * @param stream
     */
    @Override
    public void processByteStream(byte[] stream) {
        //throw new UnsupportedOperationException("Add code here");

        int pointer = 0;
        while(pointer < stream.length){
            byte[] current_data = new byte[]{stream[pointer], stream[pointer + 1]};
            AlertParser parser = new AlertParser(current_data);
            Alert alert = parser.parse();
            if(alert.getLevel() == AlertLevel.FATAL.getValue()){
                context.setTlsState(TlsState.ERROR);
            }
            pointer += 2;
        }
    }
}
