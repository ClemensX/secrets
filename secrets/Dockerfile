FROM openjdk:8
COPY . /usr/src/myapp
WORKDIR /usr/src/myapp/src/main/java/
RUN javac de/fehrprice/App.java
CMD ["java", "de.fehrprice.App"]