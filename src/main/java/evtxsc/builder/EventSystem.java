package evtxsc.builder;

import java.util.HashMap;
import java.util.Map;

/**
 * Represents the EventSystem section of a Windows Event Log entry.
 * Contains application-specific data as key-value pairs.
 *
 * @param fields A map of sub-element names and values in the System element
 */
public record EventSystem(Map<String, String> fields) {

    /**
     * Creates an EventSystem instance with an empty field map.
     */
    public EventSystem() {
        this(new HashMap<>());
    }

    /**
     * Creates an EventSystem instance with the specified fields.
     * Creates a defensive copy of the provided map.
     *
     * @param fields map of field names to values
     */
    public EventSystem { }
}
