FROM openjdk:8
COPY . /usr/src/myapp
WORKDIR /usr/src/myapp/src/main/java/
#RUN ls
RUN javac de/fehrprice/secrets/App.java
CMD ["java", "de.fehrprice.secrets.App"]