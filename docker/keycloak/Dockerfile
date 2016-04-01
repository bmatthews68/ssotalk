FROM        java
MAINTAINER  Brian Matthews <brian@btmatthews.com>

ADD keycloak-1.9.1.Final.tar.gz /opt
ADD keycloak-server.json /opt/keycloak-1.9.1.Final/standalone/configuration/
RUN /opt/keycloak-1.9.1.Final/bin/add-user.sh -r master -u admin -p everclear

EXPOSE 8080

ENTRYPOINT ["/opt/keycloak-1.9.1.Final/bin/standalone.sh","-Djboss.bind.address=0.0.0.0"]
