package evtxsc.scanners.BruteForce;

import evtxsc.scanners.Flag;

import java.util.Set;

/**
 * Represents a source flagged for a Brute Force attempt.
 */
public record BruteForceFlag(
        int eventId,
        String timeStarted,
        int numAttempts,
        long avgIntervalBetweenAttempts,
        String logonType,
        String ipAddress,
        String ipPort,
        String workstationName,
        Set<String> targetUserNames,
        String subjectUserName,
        String failureReason,
        String subStatus,
        String processName) implements Flag {

    /**
     * Formats the flag as a String for console or file output
     *
     * @return Formatted flag String
     */
    @Override
    public String format() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Brute Force Attempt Flag ===\n");
        sb.append("Event ID: ").append(eventId()).append("\n");
        sb.append("Time Started: ").append(timeStarted()).append("\n");
        sb.append("Number of Attempts: ").append(numAttempts()).append("\n");
        sb.append("Avg Interval Between Attempts: ").append(avgIntervalBetweenAttempts()).append(" ms\n");

        if (logonType() != null && !logonType().isEmpty()) {
            sb.append("Logon Type: ").append(logonType()).append("\n");
        }

        if (ipAddress() != null && !ipAddress().isEmpty()) {
            sb.append("Source IP: ").append(ipAddress());
            if (ipPort() != null && !ipPort().isEmpty()) {
                sb.append(":").append(ipPort());
            }
            sb.append("\n");
        }

        if (workstationName() != null && !workstationName().isEmpty()) {
            sb.append("Workstation: ").append(workstationName()).append("\n");
        }

        if (targetUserNames() != null && !targetUserNames().isEmpty()) {
            sb.append("Target Users: ").append(String.join(", ", targetUserNames())).append("\n");
        }

        if (subjectUserName() != null && !subjectUserName().isEmpty()) {
            sb.append("Subject User: ").append(subjectUserName()).append("\n");
        }

        if (failureReason() != null && !failureReason().isEmpty()) {
            sb.append("Failure Reason: ").append(failureReason()).append("\n");
        }

        if (subStatus() != null && !subStatus().isEmpty()) {
            sb.append("Sub Status: ").append(subStatus()).append("\n");
        }

        if (processName() != null && !processName().isEmpty()) {
            sb.append("Process: ").append(processName()).append("\n");
        }

        return sb.toString();
    }
}