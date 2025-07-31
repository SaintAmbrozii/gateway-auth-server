package com.example.gateway.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;

import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.oidc.authentication.ReactiveOidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoderFactory;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.*;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.XorServerCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.server.header.ClearSiteDataServerHttpHeadersWriter;
import org.springframework.security.web.server.util.matcher.MediaTypeServerWebExchangeMatcher;
import org.springframework.session.data.redis.config.annotation.web.server.EnableRedisWebSession;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.server.WebSession;
import org.springframework.web.server.session.WebSessionManager;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Autowired
    private ReactiveClientRegistrationRepository clientRegistrationRepository;


    @Bean
    SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity httpSecurity,
                                                  // ReactiveClientRegistrationRepository reactiveClientRegistration,
                                                  ServerOAuth2AuthorizationRequestResolver resolver,
                                                  ServerOAuth2AuthorizedClientRepository auth2AuthorizedClientRepository,
                                                  ServerLogoutSuccessHandler logoutSuccessHandler,
                                                  ServerLogoutHandler logoutHandler) {
        return httpSecurity


                .authorizeExchange(
                        authorizeExchange ->
                                authorizeExchange
                                        .pathMatchers("/",
                                                "/favicon.ico",
                                                "/actuator/**",
                                                "/access-token/**",
                                                "/id-token")
                                        .permitAll()
                                        .anyExchange()
                                        .authenticated()

                )

                .oauth2Login(oauth2Login ->
                        oauth2Login.authorizationRequestResolver(resolver)
                                .authorizedClientRepository(auth2AuthorizedClientRepository)
                                .authenticationSuccessHandler(authenticationSuccessHandler())

                )
                .oauth2Client(Customizer.withDefaults())

                .logout(logout ->
                        logout.logoutSuccessHandler(logoutSuccessHandler)
                                .logoutHandler(logoutHandler)
                )
                .csrf(csrf -> csrf
                        // Используем куки для хранения токенов CSRF. Для того, чтобы Angular
                        // и другие приложения на JS поддерживали такой механизм, необходимо
                        // установить атрибут куки httpOnly = false.
                        // По умолчанию токены CSRF хранятся в веб-сессии.
                        .csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse())
                        // Токены CSRF доступны в качестве атрибута ServerWebExchange, это достигается
                        // за счет наличия в контексте спринга реализации интерфейса ServerCsrfTokenRequestHandler,
                        // по умолчанию используется XorServerCsrfTokenRequestAttributeHandler, который
                        // умеет маскировать токены (c помощью XOR операции) и получать их значение обратно. В данном случае,
                        // конфигурация полностью совпадает с дефолтной и приведена здесь в качестве примера.
                        .csrfTokenRequestHandler(new XorServerCsrfTokenRequestAttributeHandler()))

                .exceptionHandling(
                        exceptionHandlingSpec -> exceptionHandlingSpec
                                .authenticationEntryPoint(authenticationEntryPoint())
                )



                .build();
    }

    @Bean
    public ServerOAuth2AuthorizationRequestResolver requestResolver(ReactiveClientRegistrationRepository clientRegistrationRepository) {
        var resolver = new DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository);
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
        return resolver;
    }

    @Bean
    public ServerOAuth2AuthorizedClientRepository authorizedClientRepository() {
        return new WebSessionServerOAuth2AuthorizedClientRepository();
    }
    private ServerAuthenticationSuccessHandler authenticationSuccessHandler() {
        return new RedirectServerAuthenticationSuccessHandler("/id-token");
    }

    @Bean
    public ServerLogoutSuccessHandler logoutSuccessHandler(ReactiveClientRegistrationRepository clientRegistrationRepository) {
        OidcClientInitiatedServerLogoutSuccessHandler oidcLogoutSuccessHandler =
                new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository);
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}/logout");
        return oidcLogoutSuccessHandler;
    }

    @Bean
   public ServerLogoutHandler logoutHandler() {
        return new DelegatingServerLogoutHandler(
                new SecurityContextServerLogoutHandler(),
                new WebSessionServerLogoutHandler(),
                new HeaderWriterServerLogoutHandler(
                        new ClearSiteDataServerHttpHeadersWriter(ClearSiteDataServerHttpHeadersWriter.Directive.COOKIES)
                )
        );
    }
  //  @Bean
 //   public ReactiveJwtDecoderFactory<ClientRegistration> idTokenDecoderFactory() {
 //       ReactiveOidcIdTokenDecoderFactory idTokenDecoderFactory = new ReactiveOidcIdTokenDecoderFactory();
        // RSA is the default algorithm, but we are using HS256
//        idTokenDecoderFactory.setJwsAlgorithmResolver(clientRegistration -> SignatureAlgorithm.RS256);
 //       return idTokenDecoderFactory;
 //   }


    private ServerAuthenticationEntryPoint authenticationEntryPoint() {
        RedirectServerAuthenticationEntryPoint webAuthenticationEntryPoint =
                new RedirectServerAuthenticationEntryPoint("/oauth2/authorization/gateway-oidc");
        MediaTypeServerWebExchangeMatcher textHtmlMatcher =
                new MediaTypeServerWebExchangeMatcher(MediaType.TEXT_HTML);
        textHtmlMatcher.setUseEquals(true);

        return new DelegatingServerAuthenticationEntryPoint(
                new DelegatingServerAuthenticationEntryPoint.DelegateEntry(textHtmlMatcher, webAuthenticationEntryPoint));
   }

    @Bean
    public WebClient webClient(ReactiveOAuth2AuthorizedClientManager authorizedClientManager) {
        ServerOAuth2AuthorizedClientExchangeFilterFunction oauth2Client =
                new ServerOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
        oauth2Client.setDefaultOAuth2AuthorizedClient(true);
        return WebClient.builder()
                .filter(oauth2Client)
                .build();
    }

    @Bean
    @Primary
    public ReactiveOAuth2AuthorizedClientManager authorizedClientManager(ReactiveClientRegistrationRepository clientRegistrationRepository,
                                                                         ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
        ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider =
                ReactiveOAuth2AuthorizedClientProviderBuilder.builder()
                        .authorizationCode()
                        .refreshToken()
                        .clientCredentials()
                        .build();
        DefaultReactiveOAuth2AuthorizedClientManager authorizedClientManager =
                new DefaultReactiveOAuth2AuthorizedClientManager(clientRegistrationRepository, authorizedClientRepository);
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
        return authorizedClientManager;
    }

    @Bean
    public WebFilter csrfWebFilter() {
        return (exchange, chain) -> {
            exchange.getResponse().beforeCommit(() -> Mono.defer(() -> {
                Mono<CsrfToken> csrfToken = exchange.getAttribute(CsrfToken.class.getName());
                return csrfToken != null ? csrfToken.then() : Mono.empty();
            }));
            return chain.filter(exchange);
        };
    }






  //  private Mono<Void> authenticationSuccessHandler(
  //          WebFilterExchange webFilterExchange, Authentication authentication) {
  //      return buildResponse(webFilterExchange, HttpStatus.OK, Map.of("status", "LoginSuccess"));
 //   }

 //   private Mono<Void> authenticationFailureHandler(
//            WebFilterExchange webFilterExchange, AuthenticationException exception) {
//        return buildResponse(
//                webFilterExchange, HttpStatus.UNAUTHORIZED, Map.of("status", "Authentication Failed"));
//    }

  //  private Mono<Void> authenticationEntryPoint(
 //           ServerWebExchange exchange, AuthenticationException ex) {
 //       ServerHttpResponse response = exchange.getResponse();
 //       response.setStatusCode(HttpStatus.UNAUTHORIZED);
 //       DataBuffer result =
//                response
//                        .bufferFactory()
 //                       .wrap(Map.of("status", "Login to access APIs"));
//        return response.writeWith(Mono.just(result));
//    }

  //  private Mono<Void> buildResponse(
  //          WebFilterExchange webFilterExchange, HttpStatus status, Map<String, String> message) {
 //       ServerHttpResponse response = webFilterExchange.getExchange().getResponse();
 //       response.setStatusCode(status);
  //      response.getHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
  //      DataBuffer result =
  //              response.bufferFactory().wrap(message);
  //      return response.writeWith(Mono.just(result));
  //  }









}
