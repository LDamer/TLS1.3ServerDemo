package de.rub.nds.praktikum.messages.extensions;

import de.rub.nds.praktikum.constants.ExtensionType;
import de.rub.nds.praktikum.constants.NamedGroup;
import de.rub.nds.praktikum.messages.Serializer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * This class represents a KeyShare extension. The keyshare extension is used in
 * tls 1.3 in exchange for client and server key exchange messages.
 *
 */
public class KeyShareExtension extends Extension {

    private final List<KeyShareEntry> entryList;
    private final NamedGroup group;

     /**
     * Creates entryless KeyShareExtension for use in HelloRetryRequest.
     *
     * @param group The NamedGroup transmitted to the client within a
     * HelloRetryRequest.
     */
    public KeyShareExtension(NamedGroup group) {
        super(ExtensionType.KEY_SHARE);
        this.group = group;
        this.entryList = new ArrayList<>();
    }

    /**
     * Constructor
     *
     * @param entryList A list of supported key share entries.
     */
    public KeyShareExtension(List<KeyShareEntry> entryList) {
        super(ExtensionType.KEY_SHARE);
        this.group = null;
        this.entryList = entryList;
    }

    /**
     * Constructor
     *
     * @param entry A selected key share entry.
     */
    public KeyShareExtension(KeyShareEntry entry) {
        super(ExtensionType.KEY_SHARE);
        this.group = null;
        this.entryList = new LinkedList<>();
        entryList.add(entry);
    }

    /**
     * The named group assigned to an Entryless KeyShareExtenson.
     *
     * @return A named group.
     */
    public NamedGroup getNamedGroup() {
        return this.group;
    }

    /**
     * Checks if KeyShareExtension has KeyShareEntries.
     *
     * @return true if KeyShareExtension has entries, false otherwise.
     */
    public boolean hasEntries() {
        return entryList.size() > 0;
    }

    /**
     * Returns a list of the key share entries
     *
     * @return An unmodifiable list of the key share entries
     */
    public List<KeyShareEntry> getEntryList() {
        return Collections.unmodifiableList(entryList);
    }

    /**
     * Return a key share extension serializer
     *
     * @return A key share extension serializer
     */
    @Override
    public Serializer getSerializer() {
        return new KeyShareExtensionSerializer(this);
    }
}
