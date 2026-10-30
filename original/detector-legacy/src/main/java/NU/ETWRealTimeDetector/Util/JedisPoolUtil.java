package NU.ETWRealTimeDetector.Util;

import NU.ETWRealTimeDetector.SysConfig;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
import redis.clients.jedis.params.SetParams;

public class JedisPoolUtil {

    private static final String redisHost = SysConfig.getString("RedisHost", "127.0.0.1");
    private static final Integer redisPort = SysConfig.getInteger("RedisPort", 6379);
    private static final String redisPassword = SysConfig.getString("RedisPassword", "");

    private static int timeout = 10 * 1000;

    private static JedisPool jedisPool;

    static {
        JedisPoolConfig config = new JedisPoolConfig();
        config.setTimeBetweenEvictionRunsMillis(30 * 1000);
        // 资源数控制参数
        config.setMaxTotal(10);
        config.setMaxIdle(10);
        config.setMinIdle(0);
        config.setJmxEnabled(true);

        config.setBlockWhenExhausted(true);
        config.setMaxWaitMillis(10 * 1000);
        config.setTestOnBorrow(true);
//            config.setTestOnReturn(true);

        jedisPool = new JedisPool(config, redisHost, redisPort, timeout, redisPassword);

    }

    public static Jedis getJedis() {
        return jedisPool.getResource();
    }

    public static void release(Jedis jedis) {
        if(jedis != null){
            jedis.close();
        }
    }

    public static String set(String key,String value) {
        Jedis jedis = null;
        String set = null;
        try {
            jedis = jedisPool.getResource();
            set = jedis.set(key, value);
        }catch (Exception e){
            jedisPool.returnBrokenResource(jedis);
            e.printStackTrace();
        }finally {
            release(jedis);
        }
        return set;
    }

    public static String set(String key,String value,int dbIndex) {
        Jedis jedis = null;
        String set = null;
        try {
            jedis = jedisPool.getResource();
            jedis.select(dbIndex);
            set = jedis.set(key, value);
        }catch (Exception e){
            jedisPool.returnBrokenResource(jedis);
            e.printStackTrace();
        }finally {
            release(jedis);
        }
        return set;
    }

    public static String set(String key, String value, SetParams setParams) {
        Jedis jedis = null;
        String set = null;
        try {
            jedis = jedisPool.getResource();
            set = jedis.set(key, value, setParams);
        }catch (Exception e){
            jedisPool.returnBrokenResource(jedis);
            e.printStackTrace();
        }finally {
            release(jedis);
        }
        return set;
    }

    public static String get(String key) {
        Jedis jedis = null;
        String set = null;
        try {
            jedis = jedisPool.getResource();
            set = jedis.get(key);
        }catch (Exception e){
            jedisPool.returnBrokenResource(jedis);
            e.printStackTrace();
        }finally {
            release(jedis);
        }
        return set;
    }

    public static String get(String key,int dbIndex) {
        Jedis jedis = null;
        String set = null;
        try {
            jedis = jedisPool.getResource();
            jedis.select(dbIndex);
            set = jedis.get(key);
        }catch (Exception e){
            jedisPool.returnBrokenResource(jedis);
            e.printStackTrace();
        }finally {
            release(jedis);
        }
        return set;
    }


    public static Boolean exists(String key) {
        Jedis jedis = null;
        Boolean set = null;
        try {
            jedis = jedisPool.getResource();
            set = jedis.exists(key);
        }catch (Exception e){
            jedisPool.returnBrokenResource(jedis);
            e.printStackTrace();
        }finally {
            release(jedis);
        }
        return set;
    }

    public static Boolean exists(String key,int dbIndex) {
        Jedis jedis = null;
        Boolean set = null;
        try {
            jedis = jedisPool.getResource();
            jedis.select(dbIndex);
            set = jedis.exists(key);
        }catch (Exception e){
            jedisPool.returnBrokenResource(jedis);
            e.printStackTrace();
        }finally {
            release(jedis);
        }
        return set;
    }

    public static Long delete(String...keys) {
        Jedis jedis = null;
        Long set = null;
        try {
            jedis = jedisPool.getResource();
            set = jedis.del(keys);
        }catch (Exception e){
            jedisPool.returnBrokenResource(jedis);
            e.printStackTrace();
        }finally {
            release(jedis);
        }
        return set;
    }

    public static Long delete(int dbIndex,String...keys) {
        Jedis jedis = null;
        Long set = null;
        try {
            jedis = jedisPool.getResource();
            jedis.select(dbIndex);
            set = jedis.del(keys);
        }catch (Exception e){
            jedisPool.returnBrokenResource(jedis);
            e.printStackTrace();
        }finally {
            release(jedis);
        }
        return set;
    }

    public static Long ttl(String key) {
        Jedis jedis = null;
        Long set = null;
        try {
            jedis = jedisPool.getResource();
            set = jedis.ttl(key);
        }catch (Exception e){
            jedisPool.returnBrokenResource(jedis);
            e.printStackTrace();
        }finally {
            release(jedis);
        }
        return set;
    }
    public static Boolean hexists(String key,String value) {
        Jedis jedis = null;
        Boolean set = null;
        try {
            jedis = jedisPool.getResource();
            set = jedis.hexists(key,value);
        }catch (Exception e){
            jedisPool.returnBrokenResource(jedis);
            e.printStackTrace();
        }finally {
            release(jedis);
        }
        return set;
    }

}
