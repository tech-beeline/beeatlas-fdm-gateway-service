ARG IMAGE_REGISTRY
ARG SLIM=''
FROM ${IMAGE_REGISTRY}/dockerhub/library/openjdk:17${SLIM}-buster
WORKDIR /app
RUN useradd -m -d /app -s /bin/bash -g root -u 1000 app && chown app:root .
USER app
COPY build/*.jar app.jar
COPY *.sh .
COPY runapp-java.sh runapp.sh
COPY *.crt .
USER root
COPY *.crt /usr/local/share/ca-certificates
RUN update-ca-certificates
RUN keytool -import -alias apps.yd-m6-kt22.vimpelcom -keystore $JAVA_HOME/lib/security/cacerts -file apps.yd-m6-kt22.vimpelcom.ru.crt -storepass changeit
USER app
RUN keytool -importcert -file VC_RootCA.crt -alias VC_RootCA -storepass changeit -noprompt -trustcacerts
RUN keytool -importcert -file VC_BEERootCA.crt -alias VC_BEERootCA -storepass changeit -noprompt -trustcacerts
RUN keytool -importcert -file apps.yd-m6-kt22.vimpelcom.ru.crt -alias apps.yd-m6-kt22.vimpelcom.ru -storepass changeit -noprompt -trustcacerts
EXPOSE 8080/tcp
EXPOSE 8090/tcp
EXPOSE 10260/tcp
ENTRYPOINT [ "/bin/bash", "/app/run.sh" ]
