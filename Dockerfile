# 第一阶段：构建（编译、打包）
FROM maven:3.8-eclipse-temurin-8 AS builder
WORKDIR /build
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

# 第二阶段：运行时使用 Ubuntu 基础镜像（包含完整的 libstdc++ 等）
FROM eclipse-temurin:8-jre
WORKDIR /app
COPY --from=builder /build/target/unidbg-boot-server-*.jar app.jar
EXPOSE 9999
ENTRYPOINT ["java", "-jar", "app.jar"]
