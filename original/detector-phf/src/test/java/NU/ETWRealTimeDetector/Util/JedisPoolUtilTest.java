package NU.ETWRealTimeDetector.Util;

import NU.ETWRealTimeDetector.SysConfig;
import org.junit.Before;
import org.junit.Test;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.params.SetParams;


public class JedisPoolUtilTest {
    @Before
    public void setup(){
        SysConfig.setString("RedisHost", "127.0.0.1");
        SysConfig.setInteger("RedisPort", 6380);
        SysConfig.setString("RedisPassword", "");
    }

    @Test
    public void testRedis(){
        // 存入redis
        try (Jedis db = JedisPoolUtil.getJedis()) {
            db.set("test", "123456", SetParams.setParams().ex(60L));
        }
    }
}