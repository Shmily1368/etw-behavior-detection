package NU.ETWRealTimeDetector.Neo4j.Message;

import java.util.HashMap;

public class DrawSensitiveProgramProcessRelationMessage {
    public DrawSensitiveProgramProcessRelationMessage(String clientId, Long uuid, String cmds, HashMap<String, String> extend) {
        this.clientId = clientId;
        this.uuid = uuid;
        this.cmds = cmds;
        this.extend = extend;
    }

    public String clientId;
    public Long uuid;
    public String cmds;
    public HashMap<String, String> extend;
}
