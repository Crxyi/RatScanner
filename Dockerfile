FROM gradle:8.10-jdk21 AS build
WORKDIR /src
COPY . .
RUN gradle --no-daemon -q fatJar

FROM eclipse-temurin:21-jre
RUN useradd --system --uid 10001 --home /app ratscanner && mkdir -p /app/data && chown ratscanner /app/data
WORKDIR /app
COPY --from=build /src/build/libs/ratscanner.jar /app/ratscanner.jar
USER ratscanner
ENV DATA_DIR=/app/data PORT=8080
EXPOSE 8080
ENTRYPOINT ["java", "-Xmx2g", "-XX:+ExitOnOutOfMemoryError", "-Djava.io.tmpdir=/tmp", "-jar", "/app/ratscanner.jar"]
