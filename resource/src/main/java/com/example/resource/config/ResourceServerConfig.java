package com.example.resource.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class ResourceServerConfig {


    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/resource/**")
                        .hasAnyAuthority("SCOPE_message.read","SCOPE_message.write")
                        .anyRequest().authenticated()
                )

        .oauth2ResourceServer(oauth->oauth.jwt(Customizer.withDefaults()));


        return http.build();
    }

//    @Bean
 //   public JwtAuthenticationConverter jwtAuthenticationConverter() {
 //       JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        // 设置 JWT 中用于标识权限的字段名为 "authorities"
 //       grantedAuthoritiesConverter.setAuthoritiesClaimName("authorities");
        // 不添加前缀，默认会加 "SCOPE_"，这里设置为空字符串
  //      grantedAuthoritiesConverter.setAuthorityPrefix("");

  //      JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        // 设置自定义的权限转换器
 //       jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
///        return jwtAuthenticationConverter;
//    }



}

