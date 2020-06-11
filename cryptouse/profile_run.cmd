rem call java -XX:FlightRecorderOptions:stackdepth=512 -XX:StartFlightRecording=disk=true,dumponexit=true,filename=recording.jfr,maxsize=4G,settings=profile -cp bin;..\crypto\target\fehrprice.crypto-0.0.1-SNAPSHOT.jar;..\crypto\target\javax.json-1.1.2.jar;..\crypto\target\javax.json-api-1.1.2.jar de.fehrprice.crypto.CurvePerfTest


     
call java -Dcom.sun.management.jmxremote -Dcom.sun.management.jmxremote.port=1099 -Dcom.sun.management.jmxremote.rmi.port=1099 -Dcom.sun.management.jmxremote.authenticate=false -Dcom.sun.management.jmxremote.ssl=false -Dcom.sun.management.jmxremote.local.only=false -cp bin;..\crypto\target\fehrprice.crypto-0.0.1-SNAPSHOT.jar;..\crypto\target\javax.json-1.1.2.jar;..\crypto\target\javax.json-api-1.1.2.jar de.fehrprice.crypto.CurvePerfTest