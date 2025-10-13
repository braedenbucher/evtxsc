package evtxsc.scanners.Powershell;

import evtxsc.scanners.Flag;
import evtxsc.scanners.Severity;

import java.util.Set;

/**
 * Represents a PowerShell script Event flagged for malicious content.
 */
public record PowershellFlag(
        int eventId,
        String timestamp,
        String scriptSnippet,
        int fullScriptLength,
        Set<String> indicators,
        Set<String> detectedUrls,
        Set<String> detectedIps,
        Severity severity,
        String scriptPath,
        String scriptBlockId) implements Flag {

    /**
     * Formats the flag as a String for console or file output
     *
     * @return Formatted flag String
     */
    @Override
    public String format() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== PowerShell Suspicious Activity Flag ===\n");
        sb.append("Event ID: ").append(eventId()).append("\n");
        sb.append("Timestamp: ").append(timestamp()).append("\n");
        sb.append("Severity: ").append(severity()).append("\n");

        if (scriptPath() != null && !scriptPath().isEmpty()) {
            sb.append("Script Path: ").append(scriptPath()).append("\n");
        }

        if (scriptBlockId() != null && !scriptBlockId().isEmpty()) {
            sb.append("Script Block ID: ").append(scriptBlockId()).append("\n");
        }

        if (indicators() != null && !indicators().isEmpty()) {
            sb.append("Indicators: ").append(String.join(", ", indicators())).append("\n");
        }

        if (detectedUrls() != null && !detectedUrls().isEmpty()) {
            sb.append("Detected URLs: ").append(String.join(", ", detectedUrls())).append("\n");
        }

        if (detectedIps() != null && !detectedIps().isEmpty()) {
            sb.append("Detected IPs: ").append(String.join(", ", detectedIps())).append("\n");
        }

        sb.append("Script Length: ").append(fullScriptLength()).append(" characters\n");

        if (scriptSnippet() != null && !scriptSnippet().isEmpty()) {
            sb.append("Script Snippet:\n");
            sb.append("  ").append(scriptSnippet().replace("\n", "\n  ")).append("\n");
        }

        return sb.toString();
    }
}