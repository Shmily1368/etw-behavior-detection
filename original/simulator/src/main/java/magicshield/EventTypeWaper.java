package magicshield;

/**
 * EventTypeWaper
 */
public class EventTypeWaper {

    public EventTypeWaper(long ProviderId, int OpCode) {
        this.ProviderId = ProviderId;
        this.OpCode = OpCode;
    }

    public long ProviderId;
    public int OpCode;
}