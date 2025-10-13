package evtxsc.builder;

import java.util.HashMap;
import java.util.Map;

/**
 * Represents the EventData section of a Windows Event Log entry.
 * Contains application-specific data as key-value pairs.
 *
 * @param fields A map of sub-element names and values in the EventData element
 */
public record EventData(Map<String, String> fields) {

    /**
     * Creates an EventData instance with an empty field map.
     */
    public EventData() {
        this(new HashMap<>());
    }

    /**
     * Creates an EventData instance with the specified fields.
     * Creates a defensive copy of the provided map.
     *
     * @param fields map of field names to values
     */
    public EventData { }
}
