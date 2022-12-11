package de.rub.nds.praktikum.protocol;

import de.rub.nds.praktikum.constants.HandshakeMessageType;
import de.rub.nds.praktikum.constants.ProtocolType;
import de.rub.nds.praktikum.exception.TlsException;
import de.rub.nds.praktikum.records.Record;
import de.rub.nds.praktikum.records.RecordParser;
import de.rub.nds.praktikum.records.RecordSerializer;
import de.rub.nds.praktikum.util.Util;
//import jdk.jfr.internal.Utils;
//import sun.security.util.ByteArrays;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The record layer is the lowest layer of tls protocol stack and is responsible
 * for the encapsulation of the data from higher level protocols. Once the
 * ServerHello message is sent records are encrypted under the current handshake
 * context
 *
 */
public class RecordLayer {

    /**
     * tag length in byte
     */
    private static final int GCM_TAG_LENGTH = 16;

    private static final int GCM_IV_LENGTH = 12;

    private final OutputStream outputStream;

    private final InputStream inputStream;

    private final long timeout;

    private Cipher encryptionCipher = null;

    private Cipher decryptionCipher = null;

    private long readSequencenumber = 0;

    private long writeSequencenumber = 0;

    private boolean encryptionIsActive = false;

    private final SessionContext context;

    /**
     * Constructor
     *
     * @param outputStream output stream to which to write when sending data
     * @param inputStream input stream from which to read from to receive data
     * @param context the session context for which to create the record layer
     * for
     * @param timeout read timeout
     */
    public RecordLayer(OutputStream outputStream, InputStream inputStream, SessionContext context, long timeout) {
        this.timeout = timeout;
        this.outputStream = outputStream;
        this.inputStream = inputStream;
        this.context = context;
    }

    /**
     * Sends the provided data in record of the appropriate type.
     * The record is encrypted under the current connection state.
     * Encrypt the record if encryptionIsActive. Increase appropriate sequence numbers.
     *
     * @param data the plaintext data that should be sent
     * @param type the type of the protocol which wants to send this data
     * @throws IOException if something goes wrong during transmission
     */
    public void sendData(byte[] data, ProtocolType type) throws IOException {
        //throw new UnsupportedOperationException("Add code here")

        byte[] version = {(byte)0x03,(byte)0x03};
        int MAX_APPLICATION_BYTES = 4096 - 1/*type*/ - 2/*version*/ - 2/*length*/;

        int byte_count = 0;

        while(byte_count < data.length){
            int left = data.length - byte_count;
            int upper = left > MAX_APPLICATION_BYTES ? byte_count + MAX_APPLICATION_BYTES : byte_count + left;
            byte[] current_data = Arrays.copyOfRange(data, byte_count, upper);
            Record record = new Record(type.getByteValue(), version, current_data);
            if(encryptionIsActive){
                encrypt(record);
            }
            RecordSerializer serializer = new RecordSerializer(record);
            outputStream.write(serializer.serialize());
            byte_count += record.getData().length;
        }
    }

    /**
     * Tries to receive records from the input stream. If no data is available
     * an empty record list is returned.
     * Decrypt the record if encryptionIsActive. Increase appropriate sequence numbers.
     *
     * @return @throws IOException if an error occurred while reading from the
     * stream
     */
    public List<Record> receiveData() throws IOException {
        byte[] data = fetchData();
        if(data.length == 0){
            throw new TlsException("timeout");
        }
        //throw new UnsupportedOperationException("Add code here");
        ArrayList<Record> list = new ArrayList<>();

        //int byte_count = 0;
        while(data.length > 0) {
            //System.out.println("LAST BYTE OF VERSION " + Util.bytesToHexString(new byte[]{data[2]}));
            int len = Util.convertToInt(new byte[]{data[3],data[4]});
            byte[] current_data = Arrays.copyOfRange(data, 0, 5+len);

            RecordParser parser = new RecordParser(current_data);
            Record record = parser.parse();
            //don try decrypt the CCS
            if(encryptionIsActive && record.getType() != ProtocolType.CHANGE_CIPHER_SPEC.getByteValue()) {

                decrypt(record);
            }
            list.add(record);
            data = Arrays.copyOfRange(data, 5+len, data.length);//remove first record from array
        }
        return list;
    }


    private List<byte[]> chunkData(byte[] dataToChunk) {
        //throw new UnsupportedOperationException("Add code here");
        return null;
    }

    private byte[] fetchData() throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        long minTimeMillies = System.currentTimeMillis() + timeout;
        do {
            //waiting while no data available
        } while (minTimeMillies + timeout > System.currentTimeMillis() && inputStream.available() == 0);
        while (inputStream.available() != 0) {
            int read = inputStream.read();
            stream.write(read);
        }
        return stream.toByteArray();
    }

    /**
     * Activates the encryption with the parameters from the session context.
     *
     */
    public void activateEncryption() {
        encryptionIsActive = true;
    }
    
    /**
     * 
     * @return true if the encryption is active
     */
    public boolean isEncryptionActive() {
        return encryptionIsActive;
    }

    /**
     * Encrypts a record. Updates its type and sets the encrypted content in the
     * record.
     *
     * @param record
     */
    protected void encrypt(Record record) {
        //throw new UnsupportedOperationException("Add code here");

        byte[] plain = Util.concatenate(record.getData(), new byte[]{record.getType()});

        record.setType(ProtocolType.APPLICATION_DATA.getByteValue());
        int newL = plain.length+GCM_TAG_LENGTH;
        byte[] newLength = Util.convertIntToBytes(newL, 2);
        byte[] aad = Util.concatenate(new byte[]{record.getType()}, record.getVersion(), newLength);
        byte[] nonce = Util.concatenate(new byte[4],Util.longToBytes(writeSequencenumber, 8));
        byte[] IV_GCM = Util.XOR(nonce, context.getServerWriteIv());
        //if(IV_GCM == null){
        //    System.out.println("\n\n\nerror\n\n\n");
        //}
        try {
            SecretKey key = new SecretKeySpec(context.getServerWriteKey(), "AES");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, IV_GCM));
            cipher.updateAAD(aad);
            byte[] c = cipher.doFinal(plain);
            record.setData(c);
        }catch (Exception e){
            throw new TlsException("cant find aes gcm");
        }
        writeSequencenumber++;
    }

    /**
     * Decrypts a record. Updates the type and sets the data.
     *
     * @param record Record that should be decrypted
     */
    public void decrypt(Record record) {
        //throw new UnsupportedOperationException("Add code here");
        byte[] nonce = Util.concatenate(new byte[4],Util.longToBytes(readSequencenumber, 8));
        byte[] IV_GCM = Util.XOR(nonce, context.getClientWriteIv());
        byte[] aad = Util.concatenate(new byte[]{record.getType()}, record.getVersion(),Util.convertIntToBytes(record.getData().length,2));
        SecretKey key = new SecretKeySpec(context.getClientWriteKey(), "AES/GCM/NoPadding");
        Cipher cipher;
        //assert IV_GCM != null;
        System.out.println("------ DECRYPT ---------");
        System.out.println("readSequenceNumber= " + readSequencenumber);
        System.out.println("HEADER - type: \n" +
                Util.bytesToHexString(new byte[]{(byte)record.getType()}));
        System.out.println("HEADER - version: \n" +
                Util.bytesToHexString(record.getVersion()));
        System.out.println("HEADER - data (to encrypt):\n " +
                Util.bytesToHexString(record.getData()));
        System.out.println("KEY: \n" +
                Util.bytesToHexString(key.getEncoded()));
        System.out.println("AAD: \n" +
                Util.bytesToHexString(aad));
        System.out.println("ClientWriteIV: \n" +
                Util.bytesToHexString(context.getClientWriteIv()));
        System.out.println("------ DECRYPT ---------");
        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, IV_GCM));
            cipher.updateAAD(aad);
            byte[] c = cipher.doFinal(record.getData());
            record.setData(c);
        }catch (Exception e){
            e.printStackTrace();
            throw new TlsException("Problems with AES-GCM decrypt");
        }


        //correct type
        int plaintextLength = record.getData().length;
        byte type = record.getData()[plaintextLength-1];
        byte[] newData = Arrays.copyOfRange(record.getData(), 0, plaintextLength-1);
        record.setType(type);
        record.setData(newData);
        readSequencenumber++;
    }

    /**
     *
     */
    public void resetSequencenumbers() {
        //throw new UnsupportedOperationException("Add code here");
        readSequencenumber = 0;
        writeSequencenumber = 0;
    }

    public void setReadSequencenumber(int a){
        readSequencenumber = a;
    }
    public void setWriteSequencenumber(int a){
        writeSequencenumber = a;
    }
}
