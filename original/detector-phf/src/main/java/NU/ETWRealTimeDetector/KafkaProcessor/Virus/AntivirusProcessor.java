package NU.ETWRealTimeDetector.KafkaProcessor.Virus;

import NU.ETWRealTimeDetector.SysConfig;
import NU.ETWRealTimeDetector.elasticsearch.EventStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.update.UpdateRequest;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.index.query.BoolQueryBuilder;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.SearchHits;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * 防病毒保护
 *
 * @author lisq
 * @date 2022/3/21 4:22 下午
 */
public class AntivirusProcessor extends Thread {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static final Logger LOGGER = LoggerFactory.getLogger(AntivirusProcessor.class);


    private final LinkedBlockingQueue<DefenseWay> upstream;

    public AntivirusProcessor(LinkedBlockingQueue<DefenseWay> upstream) {
        this.upstream = upstream;
    }

    @Override
    public void run() {
        while (true) {
            try {
                DefenseWay take = upstream.take();

                SearchRequest request = new SearchRequest("event");
                BoolQueryBuilder boolBuilder = QueryBuilders.boolQuery();
                boolBuilder.must(QueryBuilders.matchQuery("id", take.getLogId()));
                SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
                searchSourceBuilder.query(boolBuilder);
                request.source(searchSourceBuilder);
                RestHighLevelClient client = EventStore.getInstance().getClient();

                SearchResponse response = client.search(request, RequestOptions.DEFAULT);
                SearchHits hits = response.getHits();
                if (hits.getTotalHits().value > 0) {
                    SearchHit hit = hits.getHits()[0];
                    String id = hit.getId();
                    Map<String, Object> updateMap = new HashMap<>();
                    updateMap.put("arguments", new HashMap<>());
                    updateMap.put("terminate", take.getTerminate());
                    UpdateRequest updateRequest = new UpdateRequest();
                    updateRequest.index("event");
                    updateRequest.id(id);
                    updateRequest.doc(OBJECT_MAPPER.writeValueAsString(updateMap), XContentType.JSON);
                    client.update(updateRequest, RequestOptions.DEFAULT);
                } else {
                    Integer count = take.getCount();
                    Thread.sleep(5000L);
                    if (count > 100) {
                        return;
                    }
                    take.setCount(++count);
                    upstream.put(take);
                }
            } catch (InterruptedException | IOException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * 判断日志是否是防御日志，如果是防御日志就不生成事件
     * 病毒防护日志直接保存为事件
     *
     * @param logMap 日志
     * @return 是病毒防护日志或客户端防御日志
     */
    public static boolean process(LinkedBlockingQueue<DefenseWay> upstream, Map<String, Object> logMap) throws IOException {
        String logName = logMap.get("log_name").toString();
        if ("ClientProtection".equals(logName)) {
            Map<String, Object> arguments = (Map<String, Object>) logMap.get("arguments");
            String virusLogName = arguments.get("log_name").toString();
            String operating = logMap.get("operating").toString();
            if (!"AntivirusProtection".equals(virusLogName) || !"Qurantine".equals(operating)) {
                return true;
            }
            String logId = arguments.get("log_id").toString();
            int result = Integer.parseInt(logMap.get("result").toString());
            DefenseWay defenseWay = new DefenseWay();
            defenseWay.setLogId(logId);
            defenseWay.setTerminate(result == 1 ? 6 : 7);
            try {
                upstream.put(defenseWay);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            return true;
        }
        return false;
    }
}
