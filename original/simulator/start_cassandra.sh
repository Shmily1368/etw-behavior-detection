#!/bin/bash

docker run -d --name cassandra \
-p 9042:9042 \
-v /Users/wangshifeng/Desktop/work/gitlab/wangshifeng/simulator/cassandraData:/var/lib/cassandra \
-v /Users/wangshifeng/Desktop/work/gitlab/wangshifeng/simulator/cassandra.yaml:/etc/cassandra/cassandra.yaml \
cassandra
