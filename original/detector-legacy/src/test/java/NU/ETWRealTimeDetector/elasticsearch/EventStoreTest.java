package NU.ETWRealTimeDetector.elasticsearch;

import org.junit.Test;

import static org.junit.Assert.*;

public class EventStoreTest {

    @Test
    public void getIdByEventId() {
        EventStore eventStore = EventStore.getInstance();
        String id = eventStore.getIdByEventId("a5628f82-4b5b-4c69-be02-c798ee3b2f39");
        assertNotNull(id);
    }

    @Test
    public void updateEvent() {
        EventStore eventStore = EventStore.getInstance();
        eventStore.updateEventGraph("a5628f82-4b5b-4c69-be02-c798ee3b2f39", "DrawAttackGraph", "test");
    }

    @Test
    public void updateEventLabel() {
        EventStore eventStore = EventStore.getInstance();
        eventStore.updateEventLabels("mH27SHcBjFK2phaG04s2", "PT8,PT16,PT18,PT1");
    }

    @Test
    public void saveEvent() {
        String event = "{\"policy_id\":0,\"log_name\":\"ExsitingMalware\",\"level\":2,\"os_version\":\"Windows\",\"ip_address\":\"\",\"source\":\"EDR\",\"event_category\":\"Malicious\",\"uuid\":\"\",\"mac\":\"\",\"result\":\"\",\"log_category\":\"Process\",\"attck_techniques\":\"\",\"os_type\":1,\"arguments\":{\"parent_process_id\":4076,\"process_id\":5444,\"sha256\":\"\",\"work_directory\":\"\",\"attack_graph\":\"\",\"parent_process_name\":\"uninitialized_process\",\"parent_process_user\":\"\",\"label\":\"PT3,PT18,PT16,PT8,PT1\",\"closed_time\":0,\"parent_process_commandline\":\"\",\"network_info\":\"\",\"process_commandline\":\"\\\"C:\\\\Users\\\\shifeng\\\\Desktop\\\\Rat\\\\Babylon 1.6.0.0\\\\55.exe\\\" \",\"update_time\":0,\"process_name\":\"55.exe\",\"process_uuid\":\"22e1c056-bbf2-3b41-b2d6-ab63c7e64730\",\"parent_process_uuid\":\"51a98da7-57c3-31ef-8f6f-b39e1a45fa82\",\"process_path\":\"C:\\\\Users\\\\shifeng\\\\Desktop\\\\Rat\\\\Babylon 1.6.0.0\\\\55.exe\",\"parent_process_path\":\"\",\"parent_process_md5\":\"\",\"process_tree\":\"\",\"md5\":\"\"},\"id\":\"22e1c056-bbf2-3b41-b2d6-ab63c7e64730\",\"operating\":\"\",\"terminate\":1,\"event\":true,\"behavior\":0,\"user\":\"\",\"attck_tactics\":\"\",\"host_name\":\"\",\"timestamp\":1611834679811}";

        EventStore eventStore = EventStore.getInstance();
        eventStore.saveWindowsEDREvent(event);
    }
}