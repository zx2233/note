

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

`SecurityContextHolder.getContext().setAuthentication(authResult);`
 `SecurityContextHolder`是对于`ThreadLocal`的封装。 `ThreadLocal`是一个线程内部的数据存储类，通过它可以在指定的线程中存储数据，数据存储以后，只有在指定线程中可以获取到存储的数据，对于其他线程来说则无法获取到数据。

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

是Authentication的实现类，可以调用AuthenticationProvider，来进行认证授权，获取Authentication给予上层放置SecurityContext中。

## AuthenticationProvider

-  an interface 

- Indicates(表示) a class can process a specific
  {@link org.springframework.security.core.Authentication} implementation.

多个实现类，用于不同逻辑的认证授权，DAO,JAAS等

## Password Encoding

Spring Security’s `PasswordEncoder` interface is used to perform a one way transformation of a password to allow the password to be stored securely. 

### DelegatingPasswordEncoder

A password encoder that delegates to another PasswordEncoder based upon a prefixed identifier.



Used for creating {@link PasswordEncoder} instances



# Filter Chain


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



## RememberMe 认证授权

![](C:\Users\xuan\Desktop\note\png\RememberMe 认证授权.png)

改换redis存储，则实现PersistentTokenRepository，改为redis实现，注入RememberMeConfigurer tokenRepository(
			PersistentTokenRepository tokenRepository)



## 认证授权

C:\Users\xuan\Desktop\note\png

![](C:\Users\xuan\Desktop\note\png\springSecurity认证授权.png)

## 鉴权

![](C:\Users\xuan\Desktop\note\png\SpringSecurity 权限验证.png)

### 实现AccessDecisionVoter类，重写Voter投票方法，实现动态路径鉴权

#### Service层无法注入Filter问题

https://jingyan.baidu.com/article/363872ec0c36e96e4ba16fd4.html

@Autowired无法注入到 自己实现的Voter类中，总显示为空指针，可能为Security先于Spring 加载，在voter方法被调用时，Service还没被加载进Spring容器

解决方法：使用构造器注入

**WebExpressionVoter应当先于自定义Voter，免于Login，error等路径的判断**。

```java
 @Bean
  public AccessDecisionManager accessDecisionManager(){
    List<AccessDecisionVoter<? extends Object>> decisionVoters
      = Arrays.asList(
      new WebExpressionVoter(),
      new RoleBasedVoter(usersService)
                      );
    return new UnanimousBased(decisionVoters);
  }
```

#### 鉴权使用AntPathMatcher匹配路径

在RBAC中，若数据库使用user-role-url控制用户访问的每一个url，应当实现路径覆盖，即 /* 对应的权限应当能访问诸如 /user/*,/content/add等需要的权限。

### Referring to Beans in Web Security Expressions



 使用

```java
http
        .authorizeRequests()
                .antMatchers("/user/**").access("@webSecurity.check(authentication,request)")
                ...
```

并同时注入自定义accessDecisionManager时，会使access("@webSecurity.check(authentication,request)")失效，报错信息为：Failed to evaluate expression




## AbstractAuthenticationProcessingFilter

### successfulAuthentication

​		收到providerManager返回的Authentication后，由此方法将Authentication放入SecurityContext

```java
SecurityContextHolder.getContext().setAuthentication(authResult);
```

## FilterComparator

 An internal use only {@link Comparator} that sorts the Security {@link Filter}

 instances to ensure they are in the correct order.



spring security指定一个order，用来做排序。

对于系统的filter的默认顺序，是在一个`FilterComparator`类中定义的



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

在 .maxSessionsPreventsLogin(true)，即前一个退出后，后一个才可以登陆的情况下，当用户在同一个浏览器登录不同账号，后一个会把前一个cookie覆盖，导致在这里无法使用前一个账号，重新登录因为有maxSessionsPreventsLogin(true)的限制，前一个账号并没有退出，导致无法登录。

**:解决办法**

可以在一个用户登录之后，除非用户注销，否则不允许访问登录页面，解决上面maxSessionsPreventsLogin(true)的问题。



**——————下面方法废除———————**

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

登录页面默认只接受post方法的账号密码进行验证

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

​	InitializeUserDetailsBeanManagerConfigurer类中会截获自定义的bean，调用DaoAuthenticationProvider的setUserDetailsService方法注入，因此只要声明为Bean，加入spring容器。











## 思路



关于springSecurity的动态权限控制，因为会使用WebExpressFilter,可能会导致，如果权限路径，存放在Authority中，则可能自定义Voter通过，WebExpressVoter不通过 。

上面是为了一次查询永久使用权限，

而如果使用每次都从数据库中匹配权限，则或许可以避开上面的问题





shiro对于数据库保存的Url路径，例如 ，admin: * /** ，user: post /user/  。
进行认证授权，授予用户后，在验证权限的过程中，与request的url使用通配符进行匹配，来确定是否具有访问权限。即，约定优于配置。



# JWT

JSON Web Token (JWT) 是 JSON 格式的被加密了的字符串。在传统的用户登录认证中，都是基于`session`的登录认证。用户登录成功，服务端会保存一个`session`，当然会给客户端一个 sessionId，客户端会把 sessionId 保存在`cookie`中，每次请求都会携带这个 sessionId。
 `cookie`+`session`这种模式通常是保存在内存中，而且服务从单服务到多服务会面临的`session`共享问题，随着用户量的增多，开销就会越大。而 JWT 不是这样的，只需要服务端生成`token`，客户端保存这个`token`，每次请求携带这个`token`，服务端认证解析。

https://www.jianshu.com/p/5b9f1f4de88d

- login登录成功后，获取SecurityContextHolder中的authentication,过滤去敏感信息比如密码，进行，JWT的签发，返回给前端
- 使用JWT进行认证授权,自定义filter，并放置在`UsernamePasswordAuthenticationFilter`过滤器之前，使jwt优先于form表单验证，优先于`FilterSecurityInterceptor`中的鉴权处理
- 在鉴权的过程中不应使用jwt，jwt不包含权限信息



### jwtFilter未完成

缺少前端签发jwt，及前端带jwt访问

# Oauth 2

http://www.ruanyifeng.com/blog/2014/05/oauth_2_0.html

[OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749#section-4.1)

- 一个应用要求 OAuth 授权，必须先到对方网站登记，让对方知道是谁在请求。例如去github中登记https://github.com/settings/applications/new登记，登记之后可以获取client_id和Client Secret

- https://github.com/login/oauth/authorize?
    client_id=24d49dd89443cf880927 获取授权码16902fc67b11df1b45eb

  http://localhost:9999/oauth/redirect?code=16902fc67b11df1b45eb

- 后端使用这个授权码，向 GitHub 请求令牌

 ```javascript
  ({
    method: 'post',
    url: 'https://github.com/login/oauth/access_token?' +
      `client_id=${clientID}&` +
      `client_secret=${clientSecret}&` +
      `code=${requestToken}`,
    headers: {
      accept: 'application/json'
    }
  });
 ```

- 作为回应，GitHub 会返回一段 JSON 数据，里面包含了令牌`accessToken`
- 有了令牌以后，就可以向 API 请求数据了

```javascript
({
  method: 'get',
  url: `https://api.github.com/user`,
  headers: {
    accept: 'application/json',
    Authorization: `token ${accessToken}`
  }
});

```

- 然后，就可以拿到用户数据，得到用户的身份

## Oauth2 Login (github登录范例)

### 1.oauth2完成认证

- 第三方应用程序向服务提供商发起授权请求
- 用户选择是否同意服务提供商给予第三方授权
- 用户同意授权后，服务提供商返回授权码到指定url
- 第三方应用使用收到的授权码向服务提供商申请令牌
- 服务提供商核对授权码，确认无误后向第三方应用发送令牌
- 第三方应用凭借令牌获取服务提供商提供的信息

在上面的流程中**，未储存**自己信息的应用视为**第三方**，**具有自己信息**的一方视为**服务提供商**

2.SpringSecurity提供权限的授予和鉴权服务

### 授权

yml配置如下:

```yml
spring:
  security:
    oauth2:
      client:
        registration:
          github:
            client-id: d8c2d80439f78fb9318c
            client-secret: d3ff455c459c7a226029d87f67cb8c430bf6e7c0
            redirect-uri: http://localhost:9999/login/oauth2/code/GitHub
```

在oauth2认证成功后，给予用户权限

```java
http
  .oauth2Login(oauth2Login ->
    oauth2Login
      .loginPage("/login")
      .defaultSuccessUrl("/hello")
      .userInfoEndpoint(userInfoEndpoint ->
        userInfoEndpoint
          .userAuthoritiesMapper(this.userAuthoritiesMapper())
      )
  )
;
private GrantedAuthoritiesMapper userAuthoritiesMapper() {
    return (authorities) -> {
      Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

      authorities.forEach(authority -> {
        if (OidcUserAuthority.class.isInstance(authority)) {
          OidcUserAuthority oidcUserAuthority = (OidcUserAuthority)authority;

          OidcIdToken idToken = oidcUserAuthority.getIdToken();
          OidcUserInfo userInfo = oidcUserAuthority.getUserInfo();
          // Map the claims found in idToken and/or userInfo
          // to one or more GrantedAuthority's and add it to mappedAuthorities
             //从服务提供商获取的userInfo中提取默认权限
          String authorityTemp = oidcUserAuthority.getAuthority();
          mappedAuthorities.add(new OidcUserAuthority(authorityTemp, idToken, userInfo));

        } else if (OAuth2UserAuthority.class.isInstance(authority)) {
          OAuth2UserAuthority oauth2UserAuthority = (OAuth2UserAuthority)authority;
          Map<String, Object> userAttributes = oauth2UserAuthority.getAttributes();
          // Map the attributes found in userAttributes
          // to one or more GrantedAuthority's and add it to mappedAuthorities
            //从服务提供商获取的userInfo中提取默认权限
          String authorityTemp = oauth2UserAuthority.getAuthority();
          mappedAuthorities.add(new OAuth2UserAuthority(authorityTemp, userAttributes));

        }
      });


      return mappedAuthorities;
    };
  }
```

### 前置条件

在github网站完成项目的oauth2前置条件配置，

https://github.com/settings/developers

配置完成后获取Client ID和Client Secret

前端页面配置超链接如下：

http://localhost:9999/oauth2/authorization/github发起授权访问

### authorization-uri

进入授权界面，用户授权

https://github.com/login/oauth/authorize?
  client_id=7e015d8ce32370079895&
  redirect_uri= http://localhost:9999/login/oauth2/code/GitHub

### redirect-uri

授权之后返回授权码

 http://localhost:9999/login/oauth2/code/GitHub?code=127f75ddc02bf44da0d2

### token-uri 

根据授权码向服务提供商请求令牌

url: 'https://github.com/login/oauth/access_token?' +
      `client_id=${clientID}&` +
      `client_secret=${clientSecret}&` +
      `code=${requestToken}`

### user-info-uri

根据令牌，向服务提供商请求资源

url: `https://api.github.com/user`,
  headers: {
    accept: 'application/json',
    Authorization: `token ${accessToken}`
  }

## CommonOAuth2Provider

`CommonOAuth2Provider` pre-defines a set of default client properties for a number of well known providers: Google, GitHub, Facebook, and Okta.

For example, the `authorization-uri`, `token-uri`, and `user-info-uri` do not change often for a Provider. Therefore, it makes sense to provide default values in order to reduce the required configuration.

## Endpoint

### Authorization Endpoint



### Token Endpoint



### Redirection Endpoint



### UserInfo Endpoint





## oauth2登录之后如何授权，怎样与表单登录衔接

第三方登录用于**用户认证**，授权需要自定义授权





## FilterChan

**Oauth2过滤器顺序**

![](C:\Users\xuan\Desktop\note\png\批注 2020-02-27 174418.png)

OAuth2AuthorizationRequestRedirectFilter
OAuth2LoginAuthenticationFilter
DefaultLoginPageGeneratingFilter

## 认证服务器Authorization server



## 资源服务器Resource server


# OpenID

 [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)

OpenID Connect 1.0 is a simple identity layer on top of the OAuth 2.0 protocol. It allows Clients to verify the identity of the End-User based on the authentication performed by an Authorization Server, as well as to obtain basic profile information about the End-User in an interoperable and REST-like manner.

OpenID Connect allows clients of all types, including Web-based, mobile, and JavaScript clients, to request and receive information about authenticated sessions and end-users. The specification suite is extensible, allowing participants to use optional features such as encryption of identity data, discovery of OpenID Providers, and session management, when it makes sense for them.



去中心化的网上身份认证系统

OpenID 是一个以用户为中心的数字身份识别框架，它具有开放、分散性。OpenID 的创建基于这样一个概念：我们可以通过 URI （又叫 URL 或网站地址）来认证一个网站的唯一身份，同理，我们也可以通过这种方式来作为用户的身份认证。









<a href="/oauth2/authorization/github">GitHub</a>





[^csrf]:  Cross-site request forgery **跨站请求伪造**

[^SpringSecurity内部]: 以`DaoAuthenticationProvider`为例

