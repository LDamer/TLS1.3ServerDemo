package de.rub.nds.praktikum.protocol;

import de.rub.nds.praktikum.constants.AlertDescription;
import de.rub.nds.praktikum.constants.AlertLevel;
import de.rub.nds.praktikum.constants.ProtocolType;
import de.rub.nds.praktikum.constants.TlsState;
import de.rub.nds.praktikum.crypto.KeyGenerator;
import de.rub.nds.praktikum.exception.TlsException;
import de.rub.nds.praktikum.records.Record;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.net.Socket;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import org.bouncycastle.crypto.tls.Certificate;

/**
 * The TLS protocol class is responsible for the orchestration of the tls
 * protocol, the handshake, the recordlayer etc.
 *
 */
public class TlsProtocol {

    private final Socket socket;
    private final RecordLayer recordLayer;
    private final HandshakeLayer handshakeLayer;
    private final ApplicationLayer applicationLayer;
    private final ChangeCipherSpecLayer changeCipherSpecLayer;
    private final AlertLayer alertLayer;
    private final List<TlsSubProtocol> layerList;
    private final SessionContext context;

    /**
     * Constructor
     *
     * @param socket the socket which should be used
     * @param cert the server certificate
     * @param key the private key for the server certificate
     * @param timeout the timeout for stream traffic
     * @throws IOException throws an io exception if something goes wrong with
     * the socket streams
     */
    public TlsProtocol(Socket socket, Certificate cert, PrivateKey key, long timeout) throws IOException {
        this.socket = socket;
        context = new SessionContext(cert, key);
        recordLayer = new RecordLayer(socket.getOutputStream(), socket.getInputStream(), context, timeout);
        handshakeLayer = new HandshakeLayer(context, recordLayer);
        applicationLayer = new ApplicationLayer(context, recordLayer);
        alertLayer = new AlertLayer(context, recordLayer);
        changeCipherSpecLayer = new ChangeCipherSpecLayer(context, recordLayer);
        layerList = new LinkedList<>();
        layerList.add(handshakeLayer);
        layerList.add(alertLayer);
        layerList.add(applicationLayer);
        layerList.add(changeCipherSpecLayer);
    }

    /**
     * Performs steps in the Statemachine until the handshake is complete or an
     * exception is raised.
     *
     * @throws IOException if something goes wrong with the socket streams
     */
    public void initSession() throws IOException {
        while (context.getTlsState() != TlsState.CONNECTED) {
            stepConnectionState();
        }
    }

    /**
     * performs a step in the statemachine
     *
     * @throws IOException if something goes wrong with the socket streams
     */
    public void stepConnectionState() throws IOException {
        //throw new UnsupportedOperationException("Add code here");
        if(context.getTlsState() == TlsState.START){
            List<Record> recordsList = recordLayer.receiveData();
            passDataToLayer(recordsList);
        }else if(context.getTlsState() == TlsState.RECVD_CH){
            //context.setTlsState(TlsState.NEGOTIATED);
            handshakeLayer.sendServerHello();
            //KeyGenerator.adjustHandshakeSecrets(context);
            //KeyGenerator.adjustHandshakeKeys(context);
            recordLayer.activateEncryption();
        }else if(context.getTlsState() == TlsState.RETRY_HELLO){
            handshakeLayer.sendHelloRetryRequest();
            //context.setTlsState(TlsState.AWAIT_RETRY_HELLO_RESPONSE);
        }else if(context.getTlsState() == TlsState.AWAIT_RETRY_HELLO_RESPONSE){
            List<Record> recordsList = recordLayer.receiveData();
            passDataToLayer(recordsList);
        }else if(context.getTlsState() == TlsState.WAIT_FINISHED){
            List<Record> recordsList = recordLayer.receiveData();
            passDataToLayer(recordsList);
        }else if(context.getTlsState() == TlsState.NEGOTIATED){
            handshakeLayer.sendCertificates();
            handshakeLayer.sendCertificateVerify();
            handshakeLayer.sendFinished();
        }

    }

    /**
     * Takes a list of records and groups them by their type. Each group is then
     * passed to the passSubGroupToLayer() function
     *
     * @param recordList A list of (maybe mixed) records
     */
    private void passDataToLayer(List<Record> recordList) {
        //throw new UnsupportedOperationException("Add code here");
        for(TlsSubProtocol p : layerList){
            ArrayList<Record> recordsOfLayer = new ArrayList<>();
            for(Record r : recordList){
                if(r.getType() == p.getType()){
                    recordsOfLayer.add(r);
                }
            }
            if(recordsOfLayer.size() > 0){
                passSubGroupToLayer(recordsOfLayer);
            }
        }

    }

    /**
     * A list consecutive records which all have the same type is passed to the
     * appropriate sub protocol
     *
     * @param recordList A list consecutive records which all have the same type
     */
    private void passSubGroupToLayer(List<Record> recordList) {
        int indexOfProtocol = -1;
        for(int i = 0; i < layerList.size(); i++){
            if(layerList.get(i).getType() == recordList.get(0).getType()){
                indexOfProtocol = i;
                break;
            }
        }
        assert indexOfProtocol >= 0;
        assert indexOfProtocol <= layerList.size();

        for(Record r : recordList){
            layerList.get(indexOfProtocol).processByteStream(r.getData());
        }
    }

    /**
     * Sends the provided data over the applicationLayer if there is a connection
     *
     * @param data the data to send
     * @throws IOException if something goes wrong with the streams
     */
    public void sendData(byte[] data) throws IOException {
        if (context.getTlsState() == TlsState.CONNECTED) {
            applicationLayer.sendData(data);
        } else {
            throw new TlsException("Not in a connected State - cannot send data");
        }
    }

    /**
     * Tries to read data from the stream
     *
     * @return the received data
     * @throws IOException if something goes wrong with the streams
     */
    public byte[] receiveData() throws IOException {
        if (context.getTlsState() != TlsState.CONNECTED) {
            throw new TlsException("Not in a connected State - cannot send data");
        }
        ByteArrayOutputStream appDataStream = new ByteArrayOutputStream();
        if (socket.isClosed() || socket.isInputShutdown() || socket.isOutputShutdown()) {
            throw new IOException("Socket closed");
        }
        List<Record> receivedRecords = recordLayer.receiveData();
        for (Record record : receivedRecords) {
            if (record.getType() != ProtocolType.APPLICATION_DATA.getByteValue()) {
                alertLayer.sendAlert(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE);
                throw new TlsException("Unexpected message");
            } else {
                appDataStream.write(applicationLayer.receiveData(record));
            }
        }
        return appDataStream.toByteArray();
    }

    /**
     * @return the session context of the protocol
     */
    public SessionContext getContext() {
        return context;
    }
    
    /**
     * @return the session recordLayer of the protocol
     */
    public RecordLayer getRecordLayer() {
        return recordLayer;
    }
}
