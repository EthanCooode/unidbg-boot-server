FROM eclipse-temurin:8-jre-alpine
WORKDIR /app
COPY target/unidbg-boot-server-0.0.1-SNAPSHOT.jar app.jar
EXPOSE 9999
ENTRYPOINT ["java", "-jar", "app.jar"]
