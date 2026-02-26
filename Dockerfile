# STEP 1 — Build stage
FROM maven:3.9.9-eclipse-temurin-21 AS builder
WORKDIR /app

# Copy Maven configuration and resolve dependencies first (to cache layers)
COPY pom.xml .
RUN mvn -B -ntp dependency:go-offline

# Copy source code and build
COPY src ./src
RUN mvn -B -ntp clean package -DskipTests

# STEP 2 — Runtime stage (lighter than JDK)
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Copy built JAR from previous stage
COPY --from=builder /app/target/*.jar app.jar

# Expose the application port (container listens on SERVER_PORT env, default 8080)
EXPOSE 8080

# Launch the gateway
ENTRYPOINT ["java", "-jar", "app.jar"]