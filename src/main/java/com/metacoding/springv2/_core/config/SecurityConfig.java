package com.metacoding.springv2._core.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.metacoding.springv2._core.filter.JwtAuthorizationFilter;

@Configuration // IoC 등록
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    // 시큐리티 필터 등록
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // 인증/권한 주소 커스터마이징
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/api/**").authenticated()
                .anyRequest().permitAll());

        // 폼 로그인 비활성화 ( POST : x-www-form-urlencoded : username, password)
        // UsernamePasswordAuthenticationFilter 비활성화 (/login 낚아채지 않는다.)
        http.formLogin(f -> f.disable());

        // Security가 베이직 인증 활성화(request 할 때마다 username, password를 요구한다.) 시킴 이걸 꺼줘야 한다.
        http.httpBasic(b -> b.disable());

        // input에 csrf 토큰 받는 것을 비활성화 한다.
        http.csrf(c -> c.disable());

        // 인증 필터를 변경
        http.addFilterBefore(new JwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}