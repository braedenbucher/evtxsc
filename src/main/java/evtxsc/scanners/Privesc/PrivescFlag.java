package evtxsc.scanners.Privesc;

import evtxsc.scanners.Flag;
import evtxsc.scanners.Severity;

import java.util.Set;

/**
 * Represents an Event flagged for privilege escalation activity.
 */
public record PrivescFlag(
        String eventId,
        String timestamp,
        Severity severity,
        String subjectUserName,
        String subjectUserSid,
        String targetUserName,
        String groupName,
        Set<String> dangerousPrivileges,
        String logonType) implements Flag {

    /**
     * Formats the flag as a String for console or file output
     *
     * @return Formatted flag String
     */
    @Override
    public String format() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Privilege Escalation Flag ===\n");
        sb.append("Event ID: ").append(eventId()).append("\n");
        sb.append("Timestamp: ").append(timestamp()).append("\n");
        sb.append("Severity: ").append(severity()).append("\n");
        sb.append("Subject User: ").append(subjectUserName())
                .append(" (").append(subjectUserSid()).append(")\n");

        if (targetUserName() != null && !targetUserName().isEmpty()) {
            sb.append("Target User: ").append(targetUserName()).append("\n");
        }

        if (groupName() != null && !groupName().isEmpty()) {
            sb.append("Group: ").append(groupName()).append("\n");
        }

        if (dangerousPrivileges() != null && !dangerousPrivileges().isEmpty()) {
            sb.append("Dangerous Privileges: ").append(String.join(", ", dangerousPrivileges())).append("\n");
        }

        if (logonType() != null && !logonType().isEmpty()) {
            sb.append("Logon Type: ").append(logonType()).append("\n");
        }

        return sb.toString();
    }
}