package NU.ETWRealTimeDetector.Util;

import NU.ETWRealTimeDetector.Framework.Node.FileNode;
import org.ehcache.Cache;
import org.ehcache.CachePersistenceException;
import org.ehcache.PersistentCacheManager;
import org.ehcache.config.builders.*;
import org.ehcache.config.units.MemoryUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

public class CacheHelper {
    private static PersistentCacheManager fileNodeCacheManager;
    private static final Logger logger = LoggerFactory.getLogger(CacheHelper.class);

    private static synchronized void ensureCacheManager() {
        if (fileNodeCacheManager == null) {
            fileNodeCacheManager = CacheManagerBuilder.newCacheManagerBuilder()
                    .using(PooledExecutionServiceConfigurationBuilder.newPooledExecutionServiceConfigurationBuilder()
                            .defaultPool("dflt", 1, 3)
                            .build())
                    .with(CacheManagerBuilder.persistence(new File(System.getProperty("user.dir") + "/cacheData", "fileNode")))
                    .build(true);
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                logger.info("shutdown hook close FileNodeCacheManager.");
                fileNodeCacheManager.close();
                try {
                    fileNodeCacheManager.destroy();
                } catch (CachePersistenceException e) {
                    e.printStackTrace();
                }
            }));
        }
    }

    public static synchronized Cache<String, FileNode> getFileNodeCache(String clientId) {
        if (fileNodeCacheManager == null) {
            ensureCacheManager();
        }

        return fileNodeCacheManager.
                createCache(clientId,
                        CacheConfigurationBuilder.newCacheConfigurationBuilder(
                                String.class,
                                FileNode.class,
                                ResourcePoolsBuilder
                                        .heap(500L)
                                        .offheap(5L, MemoryUnit.MB)
                                        //.disk(10L, MemoryUnit.MB, true)
                        )
                );
    }

    public static synchronized Cache<String, String> getMonitorCache(String clientId) {
        if (fileNodeCacheManager == null) {
            ensureCacheManager();
        }

        return fileNodeCacheManager.
                createCache(clientId + "_MonitorResult",
                        CacheConfigurationBuilder.newCacheConfigurationBuilder(
                                String.class,
                                String.class,
                                ResourcePoolsBuilder
                                        .heap(500L)
                        ).withExpiry(ExpiryPolicyBuilder.timeToLiveExpiration(java.time.Duration.ofHours(1)))
                );
    }

    public static synchronized void remove(String clientId) throws CachePersistenceException {
        if (fileNodeCacheManager != null) {
            fileNodeCacheManager.destroyCache(clientId);
        }
    }

    public static synchronized void removeMonitorCache(String clientId) throws CachePersistenceException {
        if (fileNodeCacheManager != null) {
            fileNodeCacheManager.destroyCache(clientId + "_MonitorResult");
        }
    }


}
