

Spring Security

# Project Modules

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



# Servlet应用

## SecurityContextHolder

provide access to the `SecurityContext`.

## SecurityContext

hold the `Authentication` and possibly request-specific security information.

## Authentication

 represent the principal in a Spring Security-specific manner.

## GrantedAuthority

reflect the application-wide permissions granted to a principal.

## UserDetails

provide the necessary information to build an Authentication object from your application’s DAOs or other source of security data.

## UserDetailsService

create a `UserDetails` when passed in a `String`-based username (or certificate ID or the like)









## SecurityContextPersistenceFilter

- storing the `SecurityContext` to `SecurityContextHolder` and default stores the context as an `HttpSession` attribute between HTTP requests(**SecurityContextHolder.setContext()**)

- restores the context to the `SecurityContextHolder` for each request 
- clears the `SecurityContextHolder` when the request completes
- You shouldn’t interact(交互) directly(直接地) with the `HttpSession` for security purposes. There is simply no justification(理由) for doing so - always use the `SecurityContextHolder` instead.

## AuthenticationManager 

-  just an interface ，so the implementation can be anything we choose.

- The default implementation in Spring Security is called `ProviderManager`

  

## ProviderManager

-  it delegates to a list of configured `AuthenticationProvider` s, each of which is queried in turn to see if it can perform the authentication

## AuthenticationProvider

-  an interface 

- Indicates(表示) a class can process a specific
  {@link org.springframework.security.core.Authentication} implementation.



## Password Encoding

Spring Security’s `PasswordEncoder` interface is used to perform a one way transformation of a password to allow the password to be stored securely. 

### DelegatingPasswordEncoder

A password encoder that delegates to another PasswordEncoder based upon a prefixed identifier.



Used for creating {@link PasswordEncoder} instances



# Filter Chain

## RememberMe 认证授权

![](C:\Users\DELL\Desktop\xuan\note\png\RememberMe 认证授权.png)

改换redis存储，则实现PersistentTokenRepository，改为redis实现，注入RememberMeConfigurer tokenRepository(
			PersistentTokenRepository tokenRepository)



## 认证授权



![](C:\Users\DELL\Desktop\xuan\note\png\springSecurity认证授权.png)

## 投票权限验证



![](C:\Users\DELL\Desktop\xuan\note\png\SpringSecurity 权限验证.png)





| Alias                        | Filter Class                                          | Namespace Element or Attribute           |
| ---------------------------- | ----------------------------------------------------- | ---------------------------------------- |
| CHANNEL_FILTER               | `ChannelProcessingFilter`                             | `http/intercept-url@requires-channel`    |
| SECURITY_CONTEXT_FILTER      | `SecurityContextPersistenceFilter`                    | `http`                                   |
| CONCURRENT_SESSION_FILTER    | `ConcurrentSessionFilter`                             | `session-management/concurrency-control` |
| HEADERS_FILTER               | `HeaderWriterFilter`                                  | `http/headers`                           |
| CSRF_FILTER                  | `CsrfFilter`                                          | `http/csrf`                              |
| LOGOUT_FILTER                | `LogoutFilter`                                        | `http/logout`                            |
| X509_FILTER                  | `X509AuthenticationFilter`                            | `http/x509`                              |
| PRE_AUTH_FILTER              | `AbstractPreAuthenticatedProcessingFilter` Subclasses | N/A                                      |
| CAS_FILTER                   | `CasAuthenticationFilter`                             | N/A                                      |
| FORM_LOGIN_FILTER            | `UsernamePasswordAuthenticationFilter`                | `http/form-login`                        |
| BASIC_AUTH_FILTER            | `BasicAuthenticationFilter`                           | `http/http-basic`                        |
| SERVLET_API_SUPPORT_FILTER   | `SecurityContextHolderAwareRequestFilter`             | `http/@servlet-api-provision`            |
| JAAS_API_SUPPORT_FILTER      | `JaasApiIntegrationFilter`                            | `http/@jaas-api-provision`               |
| REMEMBER_ME_FILTER           | `RememberMeAuthenticationFilter`                      | `http/remember-me`                       |
| ANONYMOUS_FILTER             | `AnonymousAuthenticationFilter`                       | `http/anonymous`                         |
| SESSION_MANAGEMENT_FILTER    | `SessionManagementFilter`                             | `session-management`                     |
| EXCEPTION_TRANSLATION_FILTER | `ExceptionTranslationFilter`                          | `http`                                   |
| FILTER_SECURITY_INTERCEPTOR  | `FilterSecurityInterceptor`                           | `http`                                   |
| SWITCH_USER_FILTER           | `SwitchUserFilter`                                    | N/A                                      |

## AbstractAuthenticationProcessingFilter

### successfulAuthentication

​		收到providerManager返回的Authentication后，由此方法将Authentication放入SecurityContext

```java
SecurityContextHolder.getContext().setAuthentication(authResult);
```

# Session Management

##  logout设置session失效，session单用户登录的问题	

//false,之前登陆的同个账号被踢掉；true,前一个退出后，后一个才可以登陆
 .maxSessionsPreventsLogin(true)

//退出后使session失效
logout().invalidateHttpSession(true)

**以上设置，当用户登录后，无法在当前账户已经登录的情况下，再次登录。而退出后，用户登录总会显示失败。**

根据SpringSecurity官方文档，进行的处理办法，官方文档解决办法及问题描述如下：

```
Adding the listener to web.xml causes an ApplicationEvent to be published to the Spring ApplicationContext every time a HttpSession commences or terminates. This is critical, as it allows the SessionRegistryImpl to be notified when a session ends.Without it, a user will never be able to log back in again once they have exceeded their session allowance, even if they log out of another session or it times out.
```

即注册HttpSessionEventPublisher到Listener，会为我们剔除过期的Session

```java
@Bean
public ServletListenerRegistrationBean httpSessionEventPublisher() {
  return new ServletListenerRegistrationBean(new HttpSessionEventPublisher());
}
```

******************************以下方法废除************

用户登录以后security 会把生成的session 放到 SessionRegistry 里面,退出成功后需要剔除此session，然而logout().invalidateHttpSession(true)可以使session失效但不会使sessionRegistry中的session失效或者剔除需要自定义方法在logout().logoutSuccessHandler中调用，删除此session

```java
@Override
public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
  System.out.println(authentication);
  System.out.println(authentication.getName());
  List<Object> o= sessionRegistry.getAllPrincipals();
  //退出成功后删除当前用户session
  for (Object principal : o) {
    if (principal instanceof User) {
      final User loggedUser = (User) principal;
      if (authentication.getName().equals(loggedUser.getUsername())) {
        List<SessionInformation> sessionsInfo = sessionRegistry.getAllSessions(principal, false);
        if (null != sessionsInfo && sessionsInfo.size() > 0) {
          for (SessionInformation sessionInformation : sessionsInfo) {
            sessionInformation.expireNow();
          }
        }
      }
    }
  }
  httpServletResponse.setStatus(HttpStatus.UNAUTHORIZED.value());
  httpServletResponse.setContentType("application/json;charset=utf-8");
  httpServletResponse.getWriter().write("退出成功，请重新登录");
}
```

# AccessDecisionManager

三种决策机制，对AccessDecisionVoter的投票结果集合进行决策

三种机制的不同可以通过源码看出

- AffirmativeBased
- ConsensusBased
- UnanimousBased

	## AccessDecisionVoter<S>

- WebExpressionVoter
- AuthenticatedVoter
- RoleVoter
- RoleHierarchyVoter

## 注意:关于使用WebExpressionVoter会使其他Voter失效

​	当use-expression=true时，WebExpressionVoter才会被启用，但却会使其他Voter失效，而在配置中use-expression默认为true

当use-expression=true，若不加入WebExpressionVoter，在程序初始化会报错。
在投票的过程中，AuthenticatedVoter和RoleVoter总是投弃权票，在AuthenticatedVoter和RoleVoter的support方法中，attribute.getAttribute()总是为空，到时投票总为弃权票

# Other

## remember-me

- 登录界面form表单中设置remember-me单选框
- 继承WebSecurityConfigurerAdapter的自定义子类配置TokenRepository
- 数据库创建放置token的table，创建表的语句在PersistentTokenRepository的实现类中或设置启动应用程序自动创建

## 运行机制

### 使用账号密码登录如何进行身份验证

在provider的子类中，loadUserByUsername(String username)用于从数据源中检索用户,additionalAuthenticationChecks( UserDetails userDetails,
			UsernamePasswordAuthenticationToken authentication)将用户输入和检索出的用户信息进行对比

验证成功调用createSuccessAuthentication()方法,创建Authentication，返回给SecurityContext

## 密码验证机制

​	将输入密码与用户存储密码进行对比，默认使用PasswordEncoder的实现类BCryptPasswordEncoder中的match()方法对比输入密码与存储密码，所以在用户存储密码时候，要使用BCryptPasswordEncoder的encode()方法进行加密

### 加密方式

​	通过注入PasswordEncoder的实现类，来进行字符串的加密

### 重新编码

在AbstractUserDetailsAuthenticationProvider的子类DaoAuthenticationProvider的createSuccessAuthentication()方法中，如果PasswordEncoder的upgradeEncoding()方法返回true，则对用户输入的密码进行编码,代替检索出的用户密码。

### 如何改变默认的BCrypt加密方式，并改变**验证凭证**中使用的PasswordEncoder

​	如果只改变密码的加密方式，在SpringSecurity内部[^SpringSecurity内部]比对用户输入与检索出的凭证时，会因为在SpringSecurity内部仍使用默认的BCryptPasswordEncoder类的match()方法进行校验，而导致match()验证方法出错。

​	所以，若改变加密方式，也应该同时改变SpringSecurity内部使用的PasswordEncoder实现类，保持一致。

​	而在SpringSecurity内部默认使用的是BCryptPasswordEncoder实现类(具体可查看PasswordEncoderFactories类)，若想改变，则需要注入passwordEncoder类型的Bean，改变SpringSecurity内部的passwordEncoder的实际类型(可查看InitializeUserDetailsBeanManagerConfigurer类，来具体查看如何改变)。



### 自定义的UserDetailsService如何注入DaoAuthenticationProvider

​	InitializeUserDetailsBeanManagerConfigurer类中会截获自定义的bean，调用DaoAuthenticationProvider的setUserDetailsService方法注入





















[^csrf]:  Cross-site request forgery **跨站请求伪造**

[^SpringSecurity内部]: 以`DaoAuthenticationProvider`为例

