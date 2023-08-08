package com.example.ourdiary.authentication.service;

import com.example.ourdiary.authentication.domain.JwtToken;
import com.example.ourdiary.authentication.domain.JwtTokens;
import com.example.ourdiary.authentication.domain.RefreshToken;
import com.example.ourdiary.authentication.repository.RefreshTokenRepository;
import com.example.ourdiary.configuration.security.jwt.JwtTokenProvider;
import com.example.ourdiary.constant.TokenStatus;
import com.example.ourdiary.exception.JwtAuthenticationException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;

    public AuthenticationServiceImpl(JwtTokenProvider jwtTokenProvider, AuthenticationManager authenticationManager, RefreshTokenRepository refreshTokenRepository) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.authenticationManager = authenticationManager;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Transactional(readOnly = true)
    @Override
    public JwtTokens issueTokens(String username, String password) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        return jwtTokenProvider.generateTokens(username, ((UserDetails) authentication.getPrincipal()).getAuthorities());
    }

    @Transactional(readOnly = true)
    @Override
    public void login(String username, String password, HttpServletResponse response) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        JwtTokens jwtTokens = jwtTokenProvider.generateTokens(username, ((UserDetails) authentication.getPrincipal()).getAuthorities());
        setJwtTokensInResponse(response, jwtTokens);
    }

    @Transactional
    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        JwtToken refreshToken = jwtTokenProvider.resolveRefreshToken(request);
        validateTokenElseThrow(refreshToken);
        disableRefreshTokenOrThrow(refreshToken);
        Cookie cookieWithJwtToken = jwtTokenProvider.createCookieWithRefreshToken(JwtToken.nullToken());
        response.addCookie(cookieWithJwtToken);
    }

    @Transactional
    @Override
    public void refresh(HttpServletRequest request, HttpServletResponse response) {
        JwtToken refreshToken = jwtTokenProvider.resolveRefreshToken(request);
        validateTokenElseThrow(refreshToken);
        disableRefreshTokenOrThrow(refreshToken);
        JwtTokens jwtTokens = jwtTokenProvider.generateTokens(refreshToken);
        setJwtTokensInResponse(response, jwtTokens);
    }

    private void disableRefreshTokenOrThrow(JwtToken refreshToken) {
        refreshTokenRepository.findByTokenAndStatus(refreshToken, TokenStatus.ENABLED).ifPresentOrElse(RefreshToken::disable, () -> {
            throw new JwtAuthenticationException("exception.authentication.invalid-token");
        });
    }

    private void validateTokenElseThrow(JwtToken refreshToken) {
        if (!jwtTokenProvider.validateToken(refreshToken)) {
            throw new JwtAuthenticationException("exception.authentication.invalid-token");
        }
    }

    private void setJwtTokensInResponse(HttpServletResponse response, JwtTokens jwtTokens) {
        JwtToken accessToken = jwtTokens.accessToken();
        response.addHeader("Authorization", "Bearer " + accessToken.stringify());
        JwtToken refreshToken = jwtTokens.refreshToken();
        response.addCookie(jwtTokenProvider.createCookieWithRefreshToken(refreshToken));
    }

}
