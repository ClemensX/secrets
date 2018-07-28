# run maven build first! then use docker-compose up to run docker-composer.yml
# test this Dockerfile with: docker build .
FROM openjdk:8
copy ./target/secrets-0.0.1-SNAPSHOT.jar /usr/myapp/
WORKDIR /usr/myapp
#RUN ls
#RUN javac de/fehrprice/secrets/App.java
CMD ["java", "-cp",  "./secrets-0.0.1-SNAPSHOT.jar", "de.fehrprice.secrets.App"]
#CMD java -cp ./secrets-0.0.1-SNAPSHOT.jar de.fehrprice.secrets.App
#CMD ["java", "-version"]