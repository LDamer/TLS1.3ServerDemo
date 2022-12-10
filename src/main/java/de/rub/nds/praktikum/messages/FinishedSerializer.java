package de.rub.nds.praktikum.messages;


/**
 * A serializer class which transforms a finished message object into its byte
 * representation
 */
public class FinishedSerializer extends Serializer<Finished> {

    private final Finished finishedMessage;

    /**
     * Constructor
     *
     * @param finishedMessage the message that should be serialized
     */
    public FinishedSerializer(Finished finishedMessage) {
        this.finishedMessage = finishedMessage;
    }

    @Override
    protected void serializeBytes() {
        //throw new UnsupportedOperationException("Add code here");
        appendBytes(finishedMessage.getVerifyData());
    }

}
