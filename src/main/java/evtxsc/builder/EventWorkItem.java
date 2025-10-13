package evtxsc.builder;

/**
 * Represents a work item for concurrent XML processing.
 *
 * @param sequenceId identifier for noting parse order
 * @param xmlSegment XML segment to be parsed
 */
public record EventWorkItem(long sequenceId, String xmlSegment) {

    /**
     * Poison pill instance used to signal consumer threads to terminate.
     */
    public static final EventWorkItem POISON_PILL = new EventWorkItem(-1L, null);

    public boolean isPoisonPill() {
        return this.sequenceId == -1L && this.xmlSegment == null;
    }
}
