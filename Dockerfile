# STEP 1 — Build stage
FROM maven:3.9.9-eclipse-temurin-21 AS builder
WORKDIR /app

# Copy Maven configuration and resolve dependencies first (to cache layers)
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source code and build
COPY src ./src
RUN mvn clean package -DskipTests

# STEP 2 — Runtime stage
FROM eclipse-temurin:21-jdk-alpine
WORKDIR /app

# Copy built JAR from previous stage
COPY --from=builder /app/target/*.jar app.jar

# Define environment variables (optional defaults)
ENV SPRING_PROFILES_ACTIVE=prod
ENV SERVER_PORT=8080

# Expose the application port
EXPOSE 8080

# Launch the gateway
ENTRYPOINT ["java", "-jar", "app.jar"]