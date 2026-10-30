package NU.ETWRealTimeDetector.Util;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.Jedis;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * @author pengtengCao
 * @date Created in 2021/12/17 10:20
 * @description：
 */
public class HostOperationMode {

    private static final Logger logger = LoggerFactory.getLogger("client_log");
    public static Integer getHostOperationMode(String uuid){
        try(Jedis jedis = JedisPoolUtil.getJedis()) {
            Map<String, String> map = jedis.hgetAll("operation_mode_hosts");
            String devops = map.get("devops");
            if(StringUtils.isNotBlank(devops)){
                List<String> list = Arrays.asList(devops.split(","));
                if(list.contains(uuid)){
                    return 1;
                }
            }
            String learn = map.get("learn");
            if(StringUtils.isNotBlank(learn)){
                List<String> list = Arrays.asList(learn.split(","));
                if(list.contains(uuid)){
                    return 2;
                }
            }
        }catch (Exception e){
            logger.error("get host operation_mode error {}",e);
        }
        return 0;
    }
}
