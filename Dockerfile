# Use an official OpenJDK runtime as a parent image
FROM openjdk:17-jdk-slim

# Set the working directory to /app
WORKDIR /app

# Copy the executable JAR file to the container
COPY target/chat-app-1.0-SNAPSHOT.jar /app/chat-app.jar

# Make port 8081 available to the world outside this container
EXPOSE 8081

# Run the JAR file
CMD ["java", "-jar", "chat-app.jar"]
