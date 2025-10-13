package evtxsc.scanners.Powershell;

import evtxsc.builder.Event;
import evtxsc.builder.EventLog;
import evtxsc.scanners.ScanResult;
import evtxsc.scanners.Severity;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Runs a Powershell Script Scan on a given Event log. Pulls executed scripts,
 * regexes obfuscation patterns, suspicious commands, network activity,
 * assigns a severity depending on content, and bundles them into
 * result objects for console or file writing.
 */
public class PowershellScanner {

    private static final int POWERSHELL_SCRIPT_BLOCK_EVENT_ID = 4104;
    private static final int SNIPPET_CONTEXT_LENGTH = 100;

    // Obfuscation patterns
    private static final Pattern BASE64_FLAG_PATTERN = Pattern.compile("-(?:enc(?:oded)?(?:command)?|e(?:c)?|en)\\s+[A-Za-z0-9+/=]{20,}", Pattern.CASE_INSENSITIVE);
    private static final Pattern BASE64_STRING_PATTERN = Pattern.compile("[A-Za-z0-9+/]{50,}={0,2}");
    private static final Pattern CHAR_CONCAT_PATTERN = Pattern.compile("\\$\\w+\\s*=\\s*['\"][^'\"]{1,3}['\"]\\s*\\+\\s*['\"][^'\"]{1,3}['\"]", Pattern.CASE_INSENSITIVE);
    private static final Pattern BACKTICK_OBFUSCATION_PATTERN = Pattern.compile("\\w*`{3,}\\w*");
    private static final Pattern COMPRESSED_PATTERN = Pattern.compile("FromBase64String|IO\\.Compression|GZipStream|DeflateStream", Pattern.CASE_INSENSITIVE);

    // Suspicious commands
    private static final Pattern DOWNLOAD_CRADLE_PATTERN = Pattern.compile("Invoke-WebRequest|Invoke-RestMethod|WebClient|DownloadString|DownloadFile|IEX|Invoke-Expression|wget|curl", Pattern.CASE_INSENSITIVE);
    private static final Pattern BYPASS_PATTERN = Pattern.compile("-ExecutionPolicy\\s+Bypass|-(?:ep|ex|executionpolicy)\\s+(?:bypass|unrestricted)|-WindowStyle\\s+Hidden|-NonInteractive|-NoProfile|-w\\s+hidden", Pattern.CASE_INSENSITIVE);
    private static final Pattern CREDENTIAL_ACCESS_PATTERN = Pattern.compile("mimikatz|Invoke-Mimikatz|Get-Credential|ConvertTo-SecureString|-AsPlainText", Pattern.CASE_INSENSITIVE);
    private static final Pattern RECON_PATTERN = Pattern.compile("Get-NetUser|Get-DomainUser|Invoke-ShareFinder|Get-NetShare|Get-NetSession|Invoke-UserHunter|Get-ADUser|Get-ADComputer", Pattern.CASE_INSENSITIVE);

    // Network activity
    private static final Pattern URL_PATTERN = Pattern.compile("https?://[\\w.-]+(?:\\.[a-zA-Z]{2,})+(?:[/\\w.-]*)*/?", Pattern.CASE_INSENSITIVE);
    private static final Pattern IP_PATTERN = Pattern.compile("(?:^|\\s|['\"])((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\\s|['\"]|$|:)");

    /**
     * Analyzes an Event Log for suspicious PowerShell script content.
     *
     * @param log the event log to analyze
     * @return results containing flagged suspicious scripts, or empty if none found
     * @throws IllegalArgumentException if log is null
     */
    public static ScanResult<PowershellFlag> runPowershellScan(EventLog log) {
        if (log == null) {
            throw new IllegalArgumentException("EventLog cannot be null");
        }

        // Filter by PowerShell Script Block events
        EventLog powershellEvents = log.filterByEventId(POWERSHELL_SCRIPT_BLOCK_EVENT_ID);
        if (powershellEvents.isEmpty()) {
            return ScanResult.empty();
        }

        // Flag suspicious events by script content
        List<PowershellFlag> flags = analyzePowershellEvents(powershellEvents);

        if (flags.isEmpty()) {
            return ScanResult.empty();
        }

        return new ScanResult<>(flags);
    }

    /**
     * Analyzes PowerShell events for indicators of suspicious content.
     *
     * @param filteredLog Log filtered to only EventID 4104
     * @return List of flag objects for suspicious scripts
     */
    private static List<PowershellFlag> analyzePowershellEvents(EventLog filteredLog) {
        List<PowershellFlag> flags = new ArrayList<>();

        for (Event event : filteredLog.events()) {
            String script = event.getEventDataField("ScriptBlockText");
            if (script == null || script.isEmpty()) {
                continue;
            }

            Set<String> indicators = new HashSet<>();
            Set<String> urls = new HashSet<>();
            Set<String> ips = new HashSet<>();
            Indicator bestMatch = null;

            // Check all patterns and track the best match for snippet extraction
            bestMatch = checkPatternExists(script, BASE64_FLAG_PATTERN, "BASE64_ENCODING", indicators, bestMatch);
            bestMatch = checkPatternExists(script, BASE64_STRING_PATTERN, "BASE64_STRING", indicators, bestMatch);
            bestMatch = checkPatternExists(script, CHAR_CONCAT_PATTERN, "CHAR_CONCATENATION", indicators, bestMatch);
            bestMatch = checkPatternExists(script, BACKTICK_OBFUSCATION_PATTERN, "BACKTICK_OBFUSCATION", indicators, bestMatch);
            bestMatch = checkPatternExists(script, COMPRESSED_PATTERN, "COMPRESSED_DATA", indicators, bestMatch);
            bestMatch = checkPatternExists(script, DOWNLOAD_CRADLE_PATTERN, "DOWNLOAD_CRADLE", indicators, bestMatch);
            bestMatch = checkPatternExists(script, BYPASS_PATTERN, "EXECUTION_BYPASS", indicators, bestMatch);
            bestMatch = checkPatternExists(script, CREDENTIAL_ACCESS_PATTERN, "CREDENTIAL_ACCESS", indicators, bestMatch);
            bestMatch = checkPatternExists(script, RECON_PATTERN, "RECONNAISSANCE", indicators, bestMatch);

            // Extract network indicators
            extractAllPatterns(script, URL_PATTERN, urls);
            extractAllPatterns(script, IP_PATTERN, ips);

            if (!urls.isEmpty()) {
                indicators.add("URLS_DETECTED");
            }
            if (!ips.isEmpty()) {
                indicators.add("IP_ADDRESSES");
            }

            // If any indicators found, create a flag
            if (!indicators.isEmpty()) {
                Severity severity = getEventSeverity(indicators);
                String snippet = extractSnippet(script, bestMatch);
                PowershellFlag flag = buildFlag(event, script, snippet, indicators, urls, ips, severity);
                if (flag != null) {
                    flags.add(flag);
                }
            }
        }

        return flags;
    }

    /**
     * Checks a pattern against the script and records indicator if found.
     *
     * @param script the script content to check
     * @param pattern the regex pattern to match
     * @param indicator the indicator name to add if pattern matches
     * @param indicators the set to add the indicator to
     * @param currentBest the current best match (highest severity)
     * @return the best match between current and new match
     */
    private static Indicator checkPatternExists(String script, Pattern pattern, String indicator,
                                                Set<String> indicators, Indicator currentBest) {
        Matcher matcher = pattern.matcher(script);
        if (matcher.find()) {
            indicators.add(indicator);
            Indicator newMatch = new Indicator(indicator, matcher.start(), matcher.end());

            // Return the match with higher severity, or first found if equal
            if (currentBest == null) {
                return newMatch;
            }

            int currentSeverity = getIndicatorSeverity(currentBest.indicator);
            int newSeverity = getIndicatorSeverity(indicator);

            return newSeverity > currentSeverity ? newMatch : currentBest;
        }
        return currentBest;
    }

    /**
     * Extracts all matches of a pattern from the script into a set.
     *
     * @param script the script content to search
     * @param pattern the regex pattern to match
     * @param results the set to add matches to
     */
    private static void extractAllPatterns(String script, Pattern pattern, Set<String> results) {
        Matcher matcher = pattern.matcher(script);
        while (matcher.find()) {
            results.add(matcher.group().trim());
        }
    }

    /**
     * Calculates a script's severity based on indicators present.
     *
     * @param indicators set of indicator names
     * @return the severity level
     */
    private static Severity getEventSeverity(Set<String> indicators) {
        int highSeverityCount = 0;
        int mediumSeverityCount = 0;

        for (String indicator : indicators) {
            int severity = getIndicatorSeverity(indicator);
            if (severity == 3) {
                highSeverityCount++;
            } else if (severity == 2) {
                mediumSeverityCount++;
            }
        }

        // HIGH: Multiple high-severity indicators or high + medium combination
        if (highSeverityCount >= 2 || (highSeverityCount >= 1 && mediumSeverityCount >= 1)) {
            return Severity.HIGH;
        }

        // MEDIUM: Single high-severity or multiple medium
        if (highSeverityCount >= 1 || mediumSeverityCount >= 2) {
            return Severity.MEDIUM;
        }

        // LOW: Everything else
        return Severity.LOW;
    }

    /**
     * Returns severity score for a given indicator (3=high, 2=medium, 1=low).
     *
     * @param indicator the indicator name
     * @return severity score
     */
    private static int getIndicatorSeverity(String indicator) {
        return switch (indicator) {
            case "DOWNLOAD_CRADLE", "CREDENTIAL_ACCESS" -> 3;
            case "BASE64_ENCODING", "EXECUTION_BYPASS", "RECONNAISSANCE", "COMPRESSED_DATA" -> 2;
            default -> 1;
        };
    }

    /**
     * Extracts a snippet of the script around the most significant indicator.
     *
     * @param script the full script content
     * @param match the indicator match to center the snippet around
     * @return a snippet of the script with context
     */
    private static String extractSnippet(String script, Indicator match) {
        if (match == null || script.length() <= SNIPPET_CONTEXT_LENGTH * 2) {
            // If script is short enough, return it all (up to reasonable length)
            return script.length() > 500 ? script.substring(0, 500) + "..." : script;
        }

        int matchCenter = (match.start + match.end) / 2;
        int snippetStart = Math.max(0, matchCenter - SNIPPET_CONTEXT_LENGTH);
        int snippetEnd = Math.min(script.length(), matchCenter + SNIPPET_CONTEXT_LENGTH);

        String snippet = script.substring(snippetStart, snippetEnd);

        if (snippetStart > 0) {
            snippet = "..." + snippet;
        }
        if (snippetEnd < script.length()) {
            snippet = snippet + "...";
        }

        return snippet;
    }

    /**
     * Builds a PowershellFlag from an event and detected indicators.
     *
     * @param event the PowerShell event
     * @param fullScript the complete script content
     * @param snippet the extracted snippet around the indicator
     * @param indicators set of detected indicators
     * @param urls set of detected URLs
     * @param ips set of detected IP addresses
     * @param severity the calculated severity level
     * @return a flag object containing all relevant information
     */
    private static PowershellFlag buildFlag(Event event, String fullScript, String snippet,
                                            Set<String> indicators, Set<String> urls,
                                            Set<String> ips, Severity severity) {
        String timestamp = event.getEventSystemField("TimeCreated.SystemTime");
        if (timestamp == null) {
            return null;
        }

        return new PowershellFlag(
                POWERSHELL_SCRIPT_BLOCK_EVENT_ID,
                timestamp,
                snippet,
                fullScript.length(),
                indicators,
                urls,
                ips,
                severity,
                event.getEventDataField("Path"),
                event.getEventDataField("ScriptBlockId")
        );
    }

    /**
     * Utility to mark location in an Event's script text and which regex pattern matched.
     *
     * @param indicator
     * @param start
     * @param end
     */
    private record Indicator(String indicator, int start, int end) {
    }
}