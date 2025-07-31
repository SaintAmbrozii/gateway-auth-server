package com.example.authserver.config;






import com.example.authserver.service.CustomUserDetailService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.AnonymousConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class DefaultSecurityConfig {

    private final CustomUserDetailService userDetailService;

    public DefaultSecurityConfig(CustomUserDetailService userDetailService) {
        this.userDetailService = userDetailService;
    }

    public static final String[] PERMIT_ALL_PATTERNS = {
            "/",
            "/v3/api-docs",
            "/ui-test",
            "/favicon.ico",
            "/js/**",
            "/css/**",
            "/api/auth/register",
            "/api/users/**",
            "/error",
            "/login/**"
    };

    @Bean
    @Order(1)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(configurer->
                        configurer.requestMatchers("/api/auth/register")
                                .permitAll()
                                .requestMatchers("/oauth2/authorize/**")
                                .permitAll()
                                .requestMatchers(PERMIT_ALL_PATTERNS)
                                .permitAll()
                                .requestMatchers("/api/users/**")
                                .hasAnyAuthority("ROLE_USER","ROLE_ADMIN")
                                .anyRequest().authenticated()
                )
                .sessionManagement
                        (httpSecuritySessionManagementConfigurer ->
                                httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
                .csrf(AbstractHttpConfigurer::disable)
                .anonymous(AnonymousConfigurer::disable)
                .formLogin(Customizer.withDefaults());



        http.cors(withDefaults());

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(10);
    }


    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        var provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailService);
        provider.setPasswordEncoder(passwordEncoder());
        return new ProviderManager(provider);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        config.addAllowedOrigin("http://localhost:3000");
        config.setAllowCredentials(true);
        source.registerCorsConfiguration("/**", config);
        return source;
    }


}
