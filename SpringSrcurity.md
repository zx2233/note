# Spring Security

## Project Modules

### Core — `spring-security-core.jar`

This module contains core authentication and access-contol classes and interfaces, remoting support, and basic provisioning APIs. It is required by any application that uses Spring Security. It supports standalone applications, remote clients, method (service layer) security, and JDBC user provisioning.

- `org.springframework.security.core`
- `org.springframework.security.access`
- `org.springframework.security.authentication`
- `org.springframework.security.provisioning`

### Remoting — `spring-security-remoting.jar`

This module provides integration(集成) with Spring Remoting. You do not need this unless you are writing a remote client that uses Spring Remoting. 

- `org.springframework.security.remoting`.

### Web — `spring-security-web.jar`

This module contains filters and related web-security infrastructure(基础结构) code. It contains anything with a servlet API dependency. You need it if you require Spring Security web authentication services and URL-based access-control

- `org.springframework.security.web`

### Config — `spring-security-config.jar`

This module contains the security namespace parsing(解析) code and Java configuration code. You need it if you use the Spring Security XML namespace for configuration or Spring Security’s Java Configuration support.

- `org.springframework.security.config`

### LDAP — `spring-security-ldap.jar`



### OAuth 2.0 Core — `spring-security-oauth2-core.jar`

contains core classes and interfaces that provide support for the OAuth 2.0 Authorization Framework and for OpenID Connect Core 1.0. It is required by applications that use OAuth 2.0 or OpenID Connect Core 1.0, such as client, resource server, and authorization server.

- `org.springframework.security.oauth2.core`

### OAuth 2.0 Client — `spring-security-oauth2-client.jar`

contains Spring Security’s client support for OAuth 2.0 Authorization Framework and OpenID Connect Core 1.0. It is required by applications that use OAuth 2.0 Login or OAuth Client support

- `org.springframework.security.oauth2.client`

### OAuth 2.0 JOSE — `spring-security-oauth2-jose.jar`

contains Spring Security’s support for the JOSE (Javascript Object Signing and Encryption) framework. The JOSE framework is intended to provide a method to securely transfer claims between parties. It is built from a collection of specifications:

- JSON Web Token (JWT)
- JSON Web Signature (JWS)
- JSON Web Encryption (JWE)
- JSON Web Key (JWK)

It contains the following top-level packages:

- `org.springframework.security.oauth2.jwt`
- `org.springframework.security.oauth2.jose`

### OAuth 2.0 Resource Server — `spring-security-oauth2-resource-server.jar`

contains Spring Security’s support for OAuth 2.0 Resource Servers. It is used to protect APIs via OAuth 2.0 Bearer Tokens. 

- `org.springframework.security.oauth2.server.resource`

### ACL — `spring-security-acl.jar`



###  CAS — `spring-security-cas.jar`



### OpenID — `spring-security-openid.jar`

contains OpenID web authentication support. It is used to authenticate users against an external OpenID server. 

-  `org.springframework.security.openid`.

It requires OpenID4Java

### Test — `spring-security-test.jar`



# Other

## CSRF

CSRF:Cross-site request forgery **跨站请求伪造**



基于Spring AOP和Servlet过滤器的安全框架。

## Authentication



## SecurityContextHolder



## AuthenticationManager 



## AuthenticationProvider

