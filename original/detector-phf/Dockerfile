ARG  DAEMON_IMAGE
FROM ${DAEMON_IMAGE}

# copy JAR into image
WORKDIR /detector
COPY rb.bin rb.bin
COPY format.txt format.txt
COPY ipip.ipdb ipip.ipdb
COPY ioc.db ioc.db
COPY trans.txt trans.txt
COPY label.txt label.txt
COPY event.txt event.txt
COPY judge.txt judge.txt
COPY monitor_judge.txt monitor_judge.txt
COPY signatures/ signatures/
COPY run_docker.sh run.sh
COPY target/lib/ lib/
COPY target/ETWRealTimeDetector-0.0.1-SNAPSHOT.jar Oct.jar

RUN chmod -R 700 ./run.sh
# run application
CMD ./run.sh

