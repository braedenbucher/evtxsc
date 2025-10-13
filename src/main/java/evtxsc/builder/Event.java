package evtxsc.builder;

/**
 * Represents a Windows Event Log entry parsed from EVTX XML.
 * Contains sequence information for ordering and parsed system/event data.
 *
 * @param sequenceId identifier for maintaining parse order
 * @param system System element from EVTX XML
 * @param eventData EventData element from EVTX XML
 */
public record Event (long sequenceId, EventSystem system, EventData eventData){

    /**
     * Builds a source key identifying the origin of this event based on logon type.
     * Uses the EVTX XML Fields to populate the key.
     * Network-based Logins: "NET:IpAddress:IpPort"
     * Workstation-based Logins: "WORKSTATION:WorkstationName"
     * Service-based Logins: "LOCAL:SubjectUserName"
     *
     * @return the source key string
     */
    public String buildSourceKey() {
        // Fetch event's logon type
        String logonType = getEventDataField("LogonType");

        if (logonType == null || logonType.isEmpty()) {
            return "UNKNOWN:NoLogonType";
        }

        // Generate key by type
        switch (logonType) {
            case "3":   // Network
            case "8":   // NetworkCleartext
            case "10":  // RemoteInteractive
            case "12":  // CachedRemoteInteractive
                String ipAddress = getEventDataField("IpAddress");
                String port = getEventDataField("IpPort");
                return String.format("NET:%s:%s", ipAddress != null ? ipAddress : "unknown", port != null ? port : "unknown");

            case "7":   // Unlock
            case "11":  // CachedInteractive
            case "13":  // CachedUnlock
                String workstation = getEventDataField("WorkstationName");
                return String.format("WORKSTATION:%s", workstation != null ? workstation : "unknown");

            case "2":   // Interactive
                String wsName = getEventDataField("WorkstationName");
                if (wsName != null && !wsName.isEmpty() && !wsName.equals("-")) {
                    return String.format("WORKSTATION:%s", wsName);
                }
                // Type 2 can be sourced from SubjectUserName

            case "0":   // System (should be rare, check anyway)
            case "4":   // Batch
            case "5":   // Service
            case "9":   // NewCredentials
                String subjectUser = getEventDataField("SubjectUserName");
                return String.format("LOCAL:%s", subjectUser != null ? subjectUser : "unknown");

            default:
                return "UNKNOWN:LogonType" + logonType;
        }
    }

    /**
     * Retrieves a System field from the Event.
     */
    public String getEventSystemField(String name) {
        return system.fields().get(name);
    }

    /**
     * Retrieves an Event Data field from the Event.
     */
    public String getEventDataField(String name) {
        return eventData.fields().get(name);
    }
}