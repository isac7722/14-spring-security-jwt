package coml.ohgiraffers.security.auth.config;

import coml.ohgiraffers.security.auth.filter.CustomAuthenticationFilter;
import coml.ohgiraffers.security.auth.handler.CustomAuthFailureHandler;
import coml.ohgiraffers.security.auth.handler.CustomAuthSuccessHandler;
import coml.ohgiraffers.security.auth.handler.CustomAuthenticationProvider;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.nio.file.Path;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableWebSecurity
public class WebSecurityConfig {

    /*
    * 1. 정적 자원에 대한 인증된 사용자 접근을 설정하는 메소드
    *
    * @return WebSecurityCustomizer
    * */

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        // 요청 리소스가 static resources을 등록하지 않겠다
        return web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());

    }

    /*
    * security filter chain 설정
    *
    * @return SecurityFilterChain
    *
    * */

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        // Cross-Site Request Forgery
        http.csrf(AbstractHttpConfigurer::disable)
                // basic filter 대신 jwtAuthorizationFilter 이걸 쓸거야!!
                .addFilter(jwtAuthorizationFilter(), BasicAuthenticationFilter.class)
                // security를 통해 session을 안 만들거야!! STATELESS
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // security에서 제공하는 form을 사용하지 않을거야!!
                .formLogin(form -> form.disable())
                // UsernamePasswordAuthenticationFilter를 대신해서 customAuthenticationFilter 를 만들거야!!
                // UsernamePasswordAuthenticationFilter는 UserDetailsService를 호출한다
                .addFilterBefore(customAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                .httpBasic(basic -> basic.disable());

        // SpringFilterChain에 걸어줌 build
        return http.build();
    }

    /*
    * 3. Authentication 의 인증 메소드를 제공하는 메니저로 Provider의 인터페이스를 의민한다
    * @return AuthenticationManager
    * */

    @Bean
    public AuthenticationManager authenticationManager(){
        return new ProviderManager(customAuthenticationProvider());
    }

    /*
    * 4. 사용자의 아이디와 패스워드를 DB와 검증하는 handler이다
    *
    * @return CustomAuthenticationProvider
    * */
    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider(){
        return new CustomAuthenticationProvider();
    }

    /*
    * 5. 비밀번호를 암호화 하는 인코더
    *
    * @return BCryptPasswordEncoder
    * */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /*
    * 6. 사용자의 인증 요청을 가로채서 로그인 로직을 수행하는 필터
    * @return CustomAuthenticationFilter
    * */
    @Bean
    public CustomAuthenticationFilter customAuthenticationFilter(){
        CustomAuthenticationFilter authenticationFilter = new CustomAuthenticationFilter(authenticationManager());
        authenticationFilter.setFilterProcessesUrl("/login");
        // 성공시
        authenticationFilter.setAuthenticationSuccessHandler(customAuthSuccessHandler());
        // 실패시
        authenticationFilter.setAuthenticationFailureHandler(customAuthFailureHandler());

        return customAuthenticationFilter();
    }

    /**
    * 7. spring security 기반의 사용자의 정보가 맞을 경우 결과를 수행하는 handler
     * @return customAuthLoginSuccessHandler
    * */
    @Bean
    public CustomAuthSuccessHandler customAuthSuccessHandler(){
        return new CustomAuthSuccessHandler();
    }

    /**
    * 8. spring security 의 사용자 정보가 맞지 않은 경우 수행되는 메서드
     * @return CustomAuthFailureHandler
    * */
    @Bean
    public CustomAuthFailureHandler customAuthFailureHandler(){
        return new CustomAuthFailureHandler();
    }






}
