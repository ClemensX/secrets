# run maven build first! then use docker-compose up to run docker-composer.yml
# test this Dockerfile with: docker build .
# java -cp .\target\secrets-0.0.1-SNAPSHOT-jar-with-dependencies.jar de.fehrprice.secrets.Server
FROM openjdk:8
copy ./target/secrets-0.0.1-SNAPSHOT-jar-with-dependencies.jar /usr/myapp/
WORKDIR /usr/myapp
#RUN ls
#RUN javac de/fehrprice/secrets/App.java
CMD ["java", "-cp",  "./secrets-0.0.1-SNAPSHOT-jar-with-dependencies.jar", "de.fehrprice.secrets.Server"]
#CMD java -cp ./secrets-0.0.1-SNAPSHOT.jar de.fehrprice.secrets.App
#CMD ["java", "-version"]

#gcloud container clusters get-credentials cluster-1 --zone europe-west4-a --project divine-glazing-211610
