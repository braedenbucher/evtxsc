package evtxsc.builder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Represents a log of Event objects parsed from EVTX XML.
 */
public record EventLog(List<Event> events) {

    /**
     * Filters an EventLog by one or more Event IDs.
     *
     * @param eventIds the Event IDs to filter by
     * @return a new EventLog containing only events matching the specified IDs
     * @throws IllegalArgumentException if no event IDs are provided
     */
    public EventLog filterByEventId(int... eventIds) {
        if (eventIds == null || eventIds.length == 0) {
            throw new IllegalArgumentException("At least one event ID must be provided");
        }

        // Convert to Set for O(1) lookup
        Set<Integer> idSet = new HashSet<>();
        for (int id : eventIds) {
            idSet.add(id);
        }

        List<Event> filtered = new ArrayList<>();
        for (Event event : events) {
            String eventIdStr = event.getEventSystemField("EventID");
            if (eventIdStr != null && !eventIdStr.isEmpty()) {
                try {
                    int eventId = Integer.parseInt(eventIdStr);
                    if (idSet.contains(eventId)) {
                        filtered.add(event);
                    }
                } catch (NumberFormatException e) {
                    // Skip events with malformed EventID
                }
            }
        }

        return new EventLog(filtered);
    }

    /**
     * Generates an empty EventLog.
     */
    public static EventLog empty() {
        return new EventLog(Collections.emptyList());
    }

    /**
     * Check if the Log is empty
     *
     * @return true if empty, false if populated
     */
    public boolean isEmpty() {
        return events.isEmpty();
    }

    /**
     * Returns count of Events in log.
     *
     * @return the size of the log
     */
    public int size() {
        return events.size();
    }
}