package evtxsc.scanners.Privesc;

import evtxsc.builder.Event;
import evtxsc.builder.EventLog;
import evtxsc.scanners.ScanResult;
import evtxsc.scanners.Severity;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Runs a Privilege Escalation Scan on a given Event log. Filters for
 * privilege assignment and group modification events, flags suspicious instances
 * of both events, and bundles them into result objects for console
 * or file writing.
 */
public class PrivescScanner {

    private static final int SPECIAL_PRIVILEGES_ASSIGNED = 4672;
    private static final int MEMBER_ADDED_GLOBAL_GROUP = 4728;
    private static final int MEMBER_ADDED_LOCAL_GROUP = 4732;

    // System/Service Account SIDs
    private static final Set<String> SYSTEM_SERVICE_SIDS = Set.of(
            "S-1-5-18",  // SYSTEM
            "S-1-5-19",  // LOCAL SERVICE
            "S-1-5-20"   // NETWORK SERVICE
    );

    // Dangerous privileges in Event 4672
    private static final Set<String> DANGEROUS_PRIVILEGES = Set.of(
            "SeDebugPrivilege",
            "SeTcbPrivilege",
            "SeLoadDriverPrivilege",
            "SeBackupPrivilege",
            "SeRestorePrivilege",
            "SeTakeOwnershipPrivilege",
            "SeAssignPrimaryTokenPrivilege",
            "SeImpersonatePrivilege",
            "SeCreateTokenPrivilege",
            "SeSecurityPrivilege",
            "SeSystemEnvironmentPrivilege",
            "SeManageVolumePrivilege",
            "SeRemoteShutdownPrivilege"
    );

    // High-risk security groups in Event 4728
    private static final Set<String> HIGH_RISK_GROUPS = Set.of(
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Administrators",
            "BUILTIN\\Administrators"
    );

    // Medium-risk security groups in Event 4732
    private static final Set<String> MEDIUM_RISK_GROUPS = Set.of(
            "Backup Operators",
            "Account Operators",
            "Server Operators",
            "Print Operators",
            "Power Users",
            "Remote Desktop Users"
    );

    /**
     * Analyzes an Event Log for potential privilege escalation activity.
     *
     * @param log the event log to analyze
     * @return results containing flagged suspicious events, or empty if none found
     * @throws IllegalArgumentException if log is null
     */
    public static ScanResult<PrivescFlag> runPrivescScan(EventLog log) {
        if (log == null) {
            throw new IllegalArgumentException("EventLog cannot be null");
        }

        List<PrivescFlag> flags = new ArrayList<>();

        // Scan for special privilege assignments (4672)
        flags.addAll(scanPrivilegeAssignments(log));

        // Scan for group membership additions (4728, 4732)
        flags.addAll(scanGroupMemberships(log));

        if (flags.isEmpty()) {
            return ScanResult.empty();
        }

        return new ScanResult<>(flags);
    }

    /**
     * Scans for suspicious privilege assignments (Event ID 4672).
     *
     * @param log the event log to analyze
     * @return list of flags for suspicious privilege assignments
     */
    private static List<PrivescFlag> scanPrivilegeAssignments(EventLog log) {
        List<PrivescFlag> flags = new ArrayList<>();
        EventLog privilegeEvents = log.filterByEventId(SPECIAL_PRIVILEGES_ASSIGNED);

        for (Event event : privilegeEvents.events()) {
            String privilegeList = event.getEventDataField("PrivilegeList");
            String subjectSid = event.getEventSystemField("Security.UserID");

            if (privilegeList == null || privilegeList.isEmpty()) {
                continue;
            }

            // Skip system/service accounts
            if (subjectSid != null && SYSTEM_SERVICE_SIDS.contains(subjectSid)) {
                continue;
            }

            // Parse space-separated privilege list
            Set<String> foundDangerousPrivileges = new HashSet<>();
            String[] privileges = privilegeList.split("\\s+");

            for (String privilege : privileges) {
                if (DANGEROUS_PRIVILEGES.contains(privilege.trim())) {
                    foundDangerousPrivileges.add(privilege.trim());
                }
            }

            // Flag if any dangerous privileges found
            if (!foundDangerousPrivileges.isEmpty()) {
                PrivescFlag flag = buildPrivilegeFlag(event, foundDangerousPrivileges);
                if (flag != null) {
                    flags.add(flag);
                }
            }
        }

        return flags;
    }

    /**
     * Scans for suspicious group membership additions (Event IDs 4728, 4732).
     *
     * @param log the event log to analyze
     * @return list of flags for suspicious group additions
     */
    private static List<PrivescFlag> scanGroupMemberships(EventLog log) {
        List<PrivescFlag> flags = new ArrayList<>();

        EventLog globalGroupEvents = log.filterByEventId(MEMBER_ADDED_GLOBAL_GROUP);
        EventLog localGroupEvents = log.filterByEventId(MEMBER_ADDED_LOCAL_GROUP);

        // Combine both event types
        List<Event> allGroupEvents = new ArrayList<>();
        allGroupEvents.addAll(globalGroupEvents.events());
        allGroupEvents.addAll(localGroupEvents.events());

        for (Event event : allGroupEvents) {
            String groupName = event.getEventDataField("TargetUserName");

            if (groupName == null || groupName.isEmpty()) {
                continue;
            }

            // Determine severity based on group
            Severity severity = determineGroupSeverity(groupName);

            if (severity != null) {
                PrivescFlag flag = buildGroupFlag(event, groupName, severity);
                if (flag != null) {
                    flags.add(flag);
                }
            }
        }

        return flags;
    }

    /**
     * Determines the security level of a group based on its name.
     *
     * @param groupName the name of the group
     * @return the security level, or null if not a monitored group
     */
    private static Severity determineGroupSeverity(String groupName) {
        // Check for exact or partial matches (case-insensitive)
        String normalizedName = groupName.toLowerCase();

        for (String highRiskGroup : HIGH_RISK_GROUPS) {
            if (normalizedName.contains(highRiskGroup.toLowerCase())) {
                return Severity.HIGH;
            }
        }

        for (String mediumRiskGroup : MEDIUM_RISK_GROUPS) {
            if (normalizedName.contains(mediumRiskGroup.toLowerCase())) {
                return Severity.MEDIUM;
            }
        }

        return null;
    }

    /**
     * Builds a PrivescFlag for a privilege assignment event.
     *
     * @param event the event containing privilege information
     * @param dangerousPrivileges the set of dangerous privileges found
     * @return a flag object, or null if required fields are missing
     */
    private static PrivescFlag buildPrivilegeFlag(Event event, Set<String> dangerousPrivileges) {
        String timestamp = event.getEventSystemField("TimeCreated.SystemTime");

        if (timestamp == null) {
            return null;
        }

        return new PrivescFlag(
                event.getEventSystemField("EventID"),
                timestamp,
                Severity.HIGH,
                event.getEventDataField("SubjectUserName"),
                event.getEventSystemField("Security.UserID"),
                null,  // targetUserName (not applicable for privilege assignments)
                null,  // groupName (not applicable for privilege assignments)
                dangerousPrivileges,
                event.getEventDataField("LogonType")
        );
    }

    /**
     * Builds a PrivescFlag for a group membership addition event.
     *
     * @param event the event containing group membership information
     * @param groupName the name of the group
     * @param severity the severity level of the group
     * @return a flag object, or null if required fields are missing
     */
    private static PrivescFlag buildGroupFlag(Event event, String groupName, Severity severity) {
        String timestamp = event.getEventSystemField("TimeCreated.SystemTime");

        if (timestamp == null) {
            return null;
        }

        return new PrivescFlag(
                event.getEventSystemField("EventID"),
                timestamp,
                severity,
                event.getEventDataField("SubjectUserName"),
                event.getEventDataField("SubjectUserSid"),
                event.getEventDataField("MemberName"),
                groupName,
                null,  // privileges (not applicable for group additions)
                null   // logonType (not applicable for group additions)
        );
    }
}