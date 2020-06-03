# Authorization server

This project is part of my demonstration project. Like any other sub-project, it is meant to show my abilities to design and maintain a system, write qualitative code (including tests, of course), learn and use some of the technologies which I use on a daily basis at work and be one more reason to explore the latest changes of used frameworks and libraries.

The role of this sub-project application in the whole project is Authorization server.

This project is based on Spring OAuth2 Boot Authorization Server, though that is [not supported anymore](https://spring.io/blog/2019/11/14/spring-security-oauth-2-0-roadmap-update). I choose such approach as easiest to learn all of the internals of and become more familiar with OAuth2, PKCE and OpenID Connect. I implemented a few additional features, such as PKCE, JWT-JWS, custom token claims, OpenID Connect support (quite poor one though), including Connect Discovery and I am going to use my results to contribute to a [recently announced](https://spring.io/blog/2020/04/15/announcing-the-spring-authorization-server) community-driven [Spring Authorization Server](https://github.com/spring-projects-experimental/spring-authorization-server) project.

## Features
   
   * [PKCE](https://tools.ietf.org/html/rfc7636)
   * JWT-JWS
   * custom token claims
   * OpenID Connect
   * Java 11
   * lombok
   * Spring Framework 5
   * Spring Boot 2
   * JUnit 5

### Prerequisites

To build the source you will need to install JDK 11.

**NOTE**: You can also install Maven (>=3.3.3) yourself and run the `mvn` command in place of `./mvnw`.

### Installing

```
$ ./mvnw install
```

**NOTE**: Be aware that you might need to increase the amount of memory available to Maven by setting a `MAVEN_OPTS` environment variable with a value like `-Xmx512m -XX:MaxPermSize=128m`.

## Running

So far:
```
$ ./mvnw spring-boot:run -Dspring-boot.run.profiles=dev,demo,with-random-key,with-simple-iss
```

## Built With

* [Maven](https://maven.apache.org/) - Dependency Management
