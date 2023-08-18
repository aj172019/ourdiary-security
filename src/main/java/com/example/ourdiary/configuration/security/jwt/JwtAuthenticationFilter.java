package com.example.ourdiary.configuration.security.jwt;

import com.example.ourdiary.authentication.domain.JwtToken;
import com.example.ourdiary.exception.JwtAuthenticationException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;


public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Value("${ourdiary.ignore-paths}")
    private List<String> ignorePaths;

    @Value("${ourdiary.ignore-paths.post}")
    private List<String> ignorePathsPost;

    private final JwtTokenProvider jwtTokenProvider;

    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (shouldIgnore(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        JwtToken jwtToken = Optional.ofNullable(jwtTokenProvider.resolveAccessToken(request)).orElseThrow(
                () -> new JwtAuthenticationException("exception.authentication.token-not-found")
        );
        if (jwtTokenProvider.validateToken(jwtToken)) {
            SecurityContextHolder.getContext().setAuthentication(jwtTokenProvider.getAuthentication(jwtToken));
        }
        filterChain.doFilter(request, response);
    }

    private boolean shouldIgnore(HttpServletRequest request) {
        String method = request.getMethod();
        String path = request.getRequestURI();
        return ignorePaths.stream().anyMatch(ignorePath -> new AntPathMatcher().match(ignorePath, path)) ||
                ignorePathsPost.stream().anyMatch(ignorePath -> method.equals(HttpMethod.POST.name()) && new AntPathMatcher().match(ignorePath, path));
    }
}
