package NU.ETWRealTimeDetector.EventRecord;

import org.junit.Test;

import static org.junit.Assert.*;

public class EventFormatTest {

    @Test
    public void loadFormat() {
        EventFormat.getArgNamesUsingEventType(EtwEventType.Callstack);
    }

}