# run maven build first! then use docker-compose up to run docker-composer.yml
# test this Dockerfile with: docker build .
# java -cp .\target\secrets-0.0.1-SNAPSHOT-jar-with-dependencies.jar de.fehrprice.secrets.Server
FROM openjdk:14
copy ./target/server-0.0.1-SNAPSHOT-jar-with-dependencies.jar /usr/myapp/
WORKDIR /usr/myapp
#EXPOSE 8000
CMD ["java", "-cp",  "./server-0.0.1-SNAPSHOT-jar-with-dependencies.jar", "de.fehrprice.secrets.Server"]

#CMD java -cp ./secrets-0.0.1-SNAPSHOT.jar de.fehrprice.secrets.App
#CMD ["java", "-version"]
