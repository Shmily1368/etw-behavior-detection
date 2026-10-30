package NU.ETWRealTimeDetector.elasticsearch;

import NU.ETWRealTimeDetector.SysConfig;
import com.alibaba.fastjson.JSONObject;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.lucene.search.TotalHits;
import org.elasticsearch.action.bulk.BulkItemResponse;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexResponse;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.update.UpdateRequest;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.index.query.MatchQueryBuilder;
import org.elasticsearch.script.Script;
import org.elasticsearch.script.ScriptType;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.SearchHits;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static java.util.Collections.singletonMap;

public class EventStore {
    private static final String elasticSearch = SysConfig.getString("ElasticSearch", "127.0.0.1:9200");
    private static final String username = SysConfig.getString("ESUserName");
    private static final String password = SysConfig.getString("ESPassword");
    private static final Logger logger = LoggerFactory.getLogger("event");

    private static EventStore instance;
    private static Gson gson = new Gson();

    private static Cache<String, String> eventId2id = Caffeine.newBuilder()
            .initialCapacity(1000)
            .maximumSize(100000)
            .expireAfterAccess(10, TimeUnit.MINUTES)
            .build();

    public static EventStore getInstance() {
        if (instance == null) {
            instance = new EventStore();
        }
        return instance;
    }

    private RestHighLevelClient client;

    public RestHighLevelClient getClient() {
        return client;
    }

    private EventStore() {
        String[] arr = elasticSearch.split(":");
        if (arr.length == 2) {
            String host = arr[0];
            int port = Integer.parseInt(arr[1]);
            /*client = new RestHighLevelClient(
                    RestClient.builder(new HttpHost(host, port, "http")
                    )
            );*/
            client = restHighLevelClient(host,port);
        }
    }

    public RestHighLevelClient restHighLevelClient(String host,Integer port) {
        final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
        credentialsProvider.setCredentials(AuthScope.ANY, new UsernamePasswordCredentials(username, password));
        RestClientBuilder builder = RestClient.builder(new HttpHost(host, port,"http"));
        builder.setRequestConfigCallback(requestConfigBuilder -> {
            requestConfigBuilder.setConnectTimeout(5000000);
            requestConfigBuilder.setSocketTimeout(5000000);
            requestConfigBuilder.setConnectionRequestTimeout(5000000);
            return requestConfigBuilder;
        });
        // 异步连接数配置
        builder.setHttpClientConfigCallback(httpClientBuilder -> {
            httpClientBuilder.setMaxConnTotal(100);
            httpClientBuilder.setMaxConnPerRoute(100);
            return httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider);
        });
        RestHighLevelClient restHighLevelClient = new RestHighLevelClient(builder);
        return restHighLevelClient;
    }

    public void saveEvent(String event) {

        JSONObject object = JSONObject.parseObject(event);
        if (!object.containsKey("status")) {
            object.put("status", 0);
            object.put("processing", System.currentTimeMillis());
        }
        String eventId = object.get("id").toString();

        String json = object.toJSONString();
        IndexRequest indexRequest = new IndexRequest("event");
        indexRequest.source(json, XContentType.JSON);
        try {
            IndexResponse indexResponse = client.index(indexRequest, RequestOptions.DEFAULT);
            String _id = indexResponse.getId();
            logger.info("save event {} {}", _id, json);
            eventId2id.put(eventId, _id);
        } catch (Exception e) {
            logger.error("write to es error", e);
        }
    }
//    public  void batchInsertDataWithIndex1(String index, List<JSONObject> datas){
//        if(ObjectUtils.isEmpty(datas)){
//            return;
//        }
//        try {
//            BulkRequest bulkRequest = new BulkRequest();
//            for (JSONObject data:datas){
//                bulkRequest.add(new IndexRequest(index).routing(data.get("log_name").toString()).source(data));
//            }
//            BulkResponse bulkResponse = client.bulk(bulkRequest, RequestOptions.DEFAULT);
//            for (BulkItemResponse bulkItemResponse : bulkResponse) {
//                IndexResponse indexResponse = (IndexResponse) bulkItemResponse.getResponse();
//                String _id = indexResponse.getId();
//                logger.info("save event {} {}", _id, json);
//                eventId2id.put(eventId, _id);
//            }
//            bulkResponse.getItems().
////            System.out.println("写入数量："+datas.size());
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }
    public void saveWindowsEDREvent(String event) {
        //
        HashMap<String, Object> map = gson.fromJson(event, new TypeToken<HashMap<String, Object>>() {
        }.getType());
        String eventId = map.get("id").toString();

        String _id = getIdByEventId(eventId);
        if (_id == null) {
            // 新增
            saveEvent(event);
        } else {
            // 更新 PHF
            Map<String, Object> arguments = (Map<String, Object>) map.get("arguments");
            String label = arguments.getOrDefault("label", "").toString();
            updateEventLabels(_id, label);
            updateEventUpdateTime(_id);
        }
    }

    public void saveGraph(String value) {
        HashMap<String, Object> map = gson.fromJson(value, new TypeToken<HashMap<String, Object>>() {
        }.getType());

        String id = map.get("id").toString();
        String type = map.get("type").toString();
        String jsonGraph = map.get("jsonGraph").toString();
        updateEventGraph(id, type, jsonGraph);
    }

    public void updateEventLabels(String id, String labels) {

        // 根据type 更新相应的字段
        UpdateRequest request = new UpdateRequest("event", id);

        Script inline = null;
        Map<String, Object> parameters = singletonMap("label", labels);

        inline = new Script(ScriptType.INLINE, "painless", "ctx._source.arguments.label = params.label", parameters);

        request.script(inline);

        try {
            client.update(request, RequestOptions.DEFAULT);
            logger.info("update event phf {} {}", id, labels);
        } catch (IOException e) {
            logger.error("更新失败", e);
        }

    }

    public void updateEventUpdateTime(String id) {

        long now = System.currentTimeMillis();
        // 根据type 更新相应的字段
        UpdateRequest request = new UpdateRequest("event", id);

        Script inline = null;
        Map<String, Object> parameters = singletonMap("update_time", now);

        inline = new Script(ScriptType.INLINE, "painless", "ctx._source.arguments.update_time = params.update_time", parameters);

        request.script(inline);

        try {
            client.update(request, RequestOptions.DEFAULT);
            logger.info("update event update time {} {}", id, now);
        } catch (IOException e) {
            logger.error("更新失败", e);
        }

    }

    public void updateEventGraph(String eventId, String type, String jsonGraph) {
        // 根据id找出数据
        String id = getIdByEventId(eventId);
        if (id == null || id.isEmpty()) {
            logger.warn("can not find event by id {}", eventId);
            return;
        }

        // 根据type 更新相应的字段
        UpdateRequest request = new UpdateRequest("event", id);

        Script inline = null;
        Map<String, Object> parameters = singletonMap("graph", jsonGraph);

        if (type.equals("DrawAttackGraph")) {
            inline = new Script(ScriptType.INLINE, "painless", "ctx._source.arguments.attack_graph = params.graph", parameters);
        } else if (type.equals("DrawProcessRelation")) {
            inline = new Script(ScriptType.INLINE, "painless", "ctx._source.arguments.process_tree = params.graph", parameters);
        }

        request.script(inline);

        try {
            client.update(request, RequestOptions.DEFAULT);
            logger.info("update event {} {} {}", eventId, type, jsonGraph);
        } catch (IOException e) {
            logger.error("更新失败", e);
        }

    }

    public String getIdByEventId(String eventId) {

        String _id = eventId2id.getIfPresent(eventId);
        if (_id != null) {
            logger.info("get id {} by event id {} from cache", _id, eventId);
            return _id;
        }

        SearchRequest searchRequest = new SearchRequest("event");

        MatchQueryBuilder matchQueryBuilder = new MatchQueryBuilder("id", eventId);

        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.query(matchQueryBuilder);
        //searchRequest.refresh(true);
        searchRequest.source(searchSourceBuilder);

        try {
            SearchResponse searchResponse = client.search(searchRequest, RequestOptions.DEFAULT);
            SearchHits hits = searchResponse.getHits();
            TotalHits totalHits = hits.getTotalHits();
            if (totalHits.value > 0) {
                SearchHit searchHit = hits.getHits()[0];
                _id = searchHit.getId();
                logger.info("get id {} by event id {} from es", _id, eventId);
                return _id;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }


}
