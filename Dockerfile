
# Usa la imagen oficial de OpenJDK
FROM mcr.microsoft.com/openjdk/jdk:21-ubuntu

#DEFINO EL DIRECTORIO DE TRABAJO
WORKDIR /app

#COPIO EL ARCHIVO JAR
COPY target/app-powerbi-0.0.1-SNAPSHOT.jar /app/apiPowerBI.jar

# Comando para ejecutar la aplicación
CMD ["java", "-Djava.awt.headless=true", "-jar",  "apiPowerBI.jar"]