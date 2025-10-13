package evtxsc.scanners;

import java.util.Collections;
import java.util.List;

/**
 * Represents a list of flags from an EventLog scan.
 *
 * @param <T> the type of flag contained in this result
 */
public record ScanResult<T extends Flag>(List<T> flags) {

    public String toFormattedString() {
        StringBuilder sb = new StringBuilder();
        sb.append("===========================================\n");
        sb.append("EVTX Scan Results\n");
        sb.append("Total Flags: ").append(flags.size()).append("\n");
        sb.append("===========================================\n\n");

        for (int i = 0; i < flags.size(); i++) {
            sb.append(flags.get(i).format());
            if (i < flags.size() - 1) {
                sb.append("\n");
            }
        }

        return sb.toString();
    }

    /**
     * Returns an empty ScanResult object.
     *
     * @param <T> the type of flag
     * @return empty ScanResult with no flags
     */
    public static <T extends Flag> ScanResult<T> empty() {
        return new ScanResult<>(Collections.emptyList());
    }

    /**
     * Checks if this result contains no flags.
     *
     * @return true if there are no flags, false otherwise
     */
    public boolean isEmpty() {
        return flags.isEmpty();
    }

    /**
     * Returns the count of flags in this result.
     *
     * @return the count of flags
     */
    public int size() {
        return flags.size();
    }
}