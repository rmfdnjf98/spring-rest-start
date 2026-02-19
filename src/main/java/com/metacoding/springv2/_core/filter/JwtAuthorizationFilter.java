package com.metacoding.springv2._core.filter;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.metacoding.springv2._core.util.JwtUtil;
import com.metacoding.springv2.user.User;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

// 인가 필터
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // localhost:8080/api/good -> 인증이 필요한 주소 요청이 들어오면 json 웹토큰이 있는지 확인하고 만들기
        // header -> Authorization : Bearer JWT토큰
        // 토큰 유무 확인 코드
        String jwt = request.getHeader("Authorization");

        if (jwt == null) {
            filterChain.doFilter(request, response);
            return;
        }

        jwt = jwt.replace("Bearer ", "");

        User user = JwtUtil.verify(jwt);

        Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(request, response);
    }
}