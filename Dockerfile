# 第一阶段：使用 eclipse-temurin 版本的 Maven 镜像进行构建
FROM maven:3.8-eclipse-temurin-8 AS builder
WORKDIR /build
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

# 第二阶段：运行时使用轻量级 eclipse-temurin JRE 镜像
FROM eclipse-temurin:8-jre-alpine
WORKDIR /app
COPY --from=builder /build/target/unidbg-boot-server-*.jar app.jar
EXPOSE 9999
ENTRYPOINT ["java", "-jar", "app.jar"]
