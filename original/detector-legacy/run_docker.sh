#!/bin/bash
set -e
#删除neo4j数据目录
rm -rf data/

delay_start=${DELAY_START:-30}

echo "delay start ${delay_start}s."

sleep ${delay_start}

# Start the first process
nohup java ${DAEMON_VM_SIZE_OPTS} ${DAEMON_GC_OPTS} -jar Daemon/daemon.jar >> Daemon/nohup.out &

status=$?
echo "start daemon: $status"
if [ $status -ne 0 ]; then
  echo "Failed to start daemon: $status"
  exit $status
fi

sleep 5
# Start the second process
java -noverify ${VM_SIZE_OPTS} ${JMX_OPTS} ${GC_OPTS} -jar Oct.jar

#status=$?
#echo "start detector: $status"
#if [ $status -ne 0 ]; then
#  echo "Failed to start detector: $status"
#  exit $status
#fi

# Naive check runs checks once a minute to see if either of the processes exited.
# This illustrates part of the heavy lifting you need to do if you want to run
# more than one service in a container. The container exits with an error
# if it detects that either of the processes has exited.
# Otherwise it loops forever, waking up every 60 seconds

#while sleep 30; do
#  ps aux |grep APTDetectorDaemon |grep -q -v grep
#  PROCESS_1_STATUS=$?
#  ps aux |grep Oct |grep -q -v grep
#  PROCESS_2_STATUS=$?
#  echo "daemon status: $PROCESS_1_STATUS"
#  echo "detector status: $PROCESS_2_STATUS"
#  # If the greps above find anything, they exit with 0 status
#  # If they are not both 0, then something is wrong
#  if [ $PROCESS_1_STATUS -ne 0 -o $PROCESS_2_STATUS -ne 0 ]; then
#    echo "One of the processes has already exited."
#    exit 1
#  fi
#done
