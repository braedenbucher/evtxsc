package evtxsc.scanners.BruteForce;

import evtxsc.builder.Event;
import evtxsc.builder.EventLog;
import evtxsc.scanners.ScanResult;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Runs a Brute Force Scan on a given Event log. Filters for
 * failed logon Events, sorts them by source, flags suspicious
 * attempts, and bundles them into result objects for console
 * or file writing.
 */
public class BruteForceScanner {

    private static final int ALLOWED_FAILURES = 2;
    private static final int TIME_WINDOW_MINUTES = 10;
    private static final int FAILED_LOGON_EVENT_ID = 4625;

    /**
     * Analyzes an Event Log for potential brute force logon attempts.
     *
     * @param log the event log to analyze
     * @return results containing flagged suspicious sources, or empty if none found
     * @throws IllegalArgumentException if log is null
     */
    public static ScanResult<BruteForceFlag> runBruteForceScan(EventLog log) {
        if (log == null) {
            throw new IllegalArgumentException("EventLog cannot be null");
        }

        // Filter by failed login IDs
        EventLog failedLogins = log.filterByEventId(FAILED_LOGON_EVENT_ID);
        if (failedLogins.isEmpty()) {
            return ScanResult.empty();
        }

        // Group failed logins by source
        Map<String, List<Event>> failedLoginsBySource = groupBySource(failedLogins);

        // Flag suspicious event chains from each source
        List<BruteForceFlag> flags = analyzeSourceAttempts(failedLoginsBySource);

        if (flags.isEmpty()) {
            return ScanResult.empty();
        }

        return new ScanResult<>(flags);
    }

    /**
     * Groups Events by their source key.
     *
     * @param failedLogins Log filtered to only EventID 4625
     * @return Map of source keys to all events containing them
     */
    private static Map<String, List<Event>> groupBySource(EventLog failedLogins) {
        Map<String, List<Event>> failedLoginsBySource = new HashMap<>();

        for (Event event : failedLogins.events()) {
            String sourceKey = event.buildSourceKey();
            failedLoginsBySource.computeIfAbsent(sourceKey, k -> new ArrayList<>()).add(event);
        }

        return failedLoginsBySource;
    }

    /**
     * Analyzes grouped attempts and creates flags for suspicious sources.
     *
     * @param failedLoginsBySource Map of source keys to all events containing them
     * @return List of flag objects from suspicious sources
     */
    private static List<BruteForceFlag> analyzeSourceAttempts(Map<String, List<Event>> failedLoginsBySource) {
        List<BruteForceFlag> flags = new ArrayList<>();

        for (Map.Entry<String, List<Event>> entry : failedLoginsBySource.entrySet()) {
            List<Event> attempts = entry.getValue();

            if (attempts.size() < ALLOWED_FAILURES) {
                continue;
            }

            // Check time window
            LocalDateTime first = parseTimestamp(attempts.getFirst().getEventSystemField("TimeCreated.SystemTime"));
            LocalDateTime last = parseTimestamp(attempts.getLast().getEventSystemField("TimeCreated.SystemTime"));

            if (first == null || last == null) {
                continue; // Skip if timestamps cannot be parsed
            }

            Duration timeSpan = Duration.between(first, last);

            if (timeSpan.compareTo(Duration.ofMinutes(TIME_WINDOW_MINUTES)) > 0) {
                continue;
            }

            // Build flag
            BruteForceFlag flag = buildFlag(attempts, timeSpan);
            if (flag != null) {
                flags.add(flag);
            }
        }

        return flags;
    }

    /**
     * Builds a BruteForceFlag from a list of attempts.
     *
     * @param attempts Events containing identical sources
     * @param timeSpan Timespan the failed logons occurred in
     * @return A flag object containing all relevant information about the source and failed logons
     */
    private static BruteForceFlag buildFlag(List<Event> attempts, Duration timeSpan) {
        Event firstEvent = attempts.getFirst();
        String firstTime = firstEvent.getEventSystemField("TimeCreated.SystemTime");

        if (firstTime == null) {
            return null; // Cannot create flag without timestamp
        }

        // Calculate avg interval
        long avgInterval = attempts.size() > 1
                ? timeSpan.getSeconds() / (attempts.size() - 1)
                : 0;

        // Collect target users
        Set<String> targetUsers = attempts.stream()
                .map(e -> e.getEventDataField("TargetUserName"))
                .filter(name -> name != null && !name.isEmpty())
                .collect(Collectors.toSet());

        return new BruteForceFlag(
                FAILED_LOGON_EVENT_ID,
                firstTime,
                attempts.size(),
                avgInterval,
                firstEvent.getEventDataField("LogonType"),
                firstEvent.getEventDataField("IpAddress"),
                firstEvent.getEventDataField("IpPort"),
                firstEvent.getEventDataField("WorkstationName"),
                targetUsers,
                firstEvent.getEventDataField("SubjectUserName"),
                firstEvent.getEventDataField("FailureReason"),
                firstEvent.getEventDataField("SubStatus"),
                firstEvent.getEventDataField("ProcessName")
        );
    }

    /**
     * Utility to parse an ISO Timestamp String for flags.
     *
     * @param timestamp String to parse
     * @return DateTime object to operate on
     */
    private static LocalDateTime parseTimestamp(String timestamp) {
        if (timestamp == null || timestamp.isEmpty()) {
            return null;
        }

        try {
            return LocalDateTime.parse(timestamp, DateTimeFormatter.ISO_DATE_TIME);
        } catch (DateTimeParseException e) {
            return null;
        }
    }
}