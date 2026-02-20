package com.metacoding.springv2._core.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.metacoding.springv2._core.filter.JwtAuthorizationFilter;
import com.metacoding.springv2._core.util.RespFilter;

@Configuration
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder encode() {
        return new BCryptPasswordEncoder();
    }

    // 시큐리티 필터 등록
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.headers(headers -> headers
                .frameOptions(frameOptions -> frameOptions.sameOrigin()));

        http.cors(c -> c.disable()); // 시큐리티 자체가 cors를 막고 있어서 이걸 비활성화 (다른 곳에서 허용 조건 코드 작성해둠)

        http.exceptionHandling(ex -> ex
                .authenticationEntryPoint( // 인증 X, session에 객체 없을 경우
                        (request, response, authException) -> RespFilter.fail(response, 401, "로그인 후 이용해주세요"))
                .accessDeniedHandler( // 권한이 없을 경우
                        (request, response, accessDeniedException) -> RespFilter.fail(response, 403, "권한이 없습니다")));

        // 서버가 클라이언트에게 jsessionid를 돌려주지 않는 설정 - stateless 상태로 설정
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // 인증/권한 주소 커스터마이징
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/api/**").authenticated()
                .requestMatchers("/admin/**").hasAnyRole("ADMIN")
                .anyRequest().permitAll());

        // 폼 로그인 비활성화 ( POST : x-www-form-urlencoded : username, password)
        http.formLogin(f -> f.disable());

        // Security가 베이직 인증 활성화(request 할 때마다 username, password를 요구한다.) 시킴 이걸 꺼줘야 한다.
        http.httpBasic(b -> b.disable());

        // csrf 비활성화
        http.csrf(c -> c.disable());

        // 인증 필터를 변경
        http.addFilterBefore(new JwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}