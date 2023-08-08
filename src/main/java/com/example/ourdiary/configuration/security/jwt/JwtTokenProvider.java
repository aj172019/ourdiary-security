package com.example.ourdiary.configuration.security.jwt;

import com.example.ourdiary.authentication.domain.JwtToken;
import com.example.ourdiary.authentication.domain.JwtTokens;
import com.example.ourdiary.authentication.domain.RefreshToken;
import com.example.ourdiary.authentication.repository.RefreshTokenRepository;
import com.example.ourdiary.exception.JwtAuthenticationException;
import com.example.ourdiary.exception.MemberNotFoundException;
import com.example.ourdiary.member.repository.MemberRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.UUID;

@Component
public class JwtTokenProvider {

    @Value("${ourdiary.jwt.secret-key}")
    private String secretKey;

    @Value("${ourdiary.jwt.token-validity-in-milliseconds}")
    private int validityInMilliseconds;

    @Value("${ourdiary.jwt.refresh-token-name}")
    private String refreshTokenName;

    @Value("${ourdiary.jwt.refresh-token-validity-in-milliseconds}")
    private int refreshTokenValidityInMilliseconds;

    @Value("${ourdiary.jwt.is-cookie-secure}")
    private boolean isCookieSecure;

    private final UserDetailsService userDetailsService;
    private final MessageSourceAccessor messageSource;
    private final RefreshTokenRepository refreshTokenRepository;
    private final MemberRepository memberRepository;

    public JwtTokenProvider(UserDetailsService userDetailsService, MessageSourceAccessor messageSource, RefreshTokenRepository refreshTokenRepository, MemberRepository memberRepository) {
        this.userDetailsService = userDetailsService;
        this.messageSource = messageSource;
        this.refreshTokenRepository = refreshTokenRepository;
        this.memberRepository = memberRepository;
    }

    public Authentication getAuthentication(JwtToken jwtToken) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(getUsername(jwtToken));
        return new UsernamePasswordAuthenticationToken(userDetails, "",userDetails.getAuthorities());
    }

    public JwtToken generateToken(String email, Collection<? extends GrantedAuthority> authorities) {
        Claims claims = Jwts.claims().setSubject(email);
        claims.put("authorities", authorities.stream().map(Object::toString).toList());
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);
        return JwtToken.create(Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact());
    }

    public JwtToken generateRefreshToken(String email) {
        Claims claims = Jwts.claims().setSubject(email);
        Date now = new Date();
        Date validity = new Date(now.getTime() + refreshTokenValidityInMilliseconds);
        JwtToken token = JwtToken.create(Jwts.builder()
                .setClaims(claims)
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(now)
                .setExpiration(validity)
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact());
        RefreshToken refreshToken = RefreshToken.create(email, token, LocalDateTime.ofInstant(validity.toInstant(), ZoneId.systemDefault()));
        refreshTokenRepository.save(refreshToken);
        return refreshToken.getToken();
    }

    public JwtTokens generateTokens(String email, Collection<? extends GrantedAuthority> authorities) {
        return JwtTokens.builder()
                .accessToken(generateToken(email, authorities))
                .refreshToken(generateRefreshToken(email))
                .build();
    }

    public JwtTokens generateTokens(JwtToken refreshToken) {
        String username = getUsername(refreshToken);
        Collection<? extends GrantedAuthority> authorities = memberRepository.findByEmail(username).orElseThrow(
                () -> new MemberNotFoundException("exception.authentication.email-not-found")
        )       .getAuthorities().stream()
                .map(authority -> new SimpleGrantedAuthority(authority.getAuthority().name()))
                .toList();
        return generateTokens(username, authorities);
    }

    public String getUsername(JwtToken jwtToken) {
        try {
            return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwtToken.stringify()).getBody().getSubject();
        } catch (Exception e) {
            throw new JwtAuthenticationException(messageSource.getMessage("exception.authentication.invalid-token"));
        }
    }

    public JwtToken resolveAccessToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken == null || !bearerToken.startsWith("Bearer ")) {
            return null;
        }
        return JwtToken.create(bearerToken.substring(7));
    }

    public JwtToken resolveRefreshToken(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null || cookies.length == 0) {
            return null;
        }
        return Arrays.stream(cookies)
                .filter(cookie -> refreshTokenName.equals(cookie.getName())).findFirst()
                .map(cookie -> JwtToken.create(cookie.getValue()))
                .orElse(null);
    }

    public boolean validateToken(JwtToken jwtToken) {
        if (jwtToken == null || jwtToken.isNull()) {
            return false;
        }
        Jws<Claims> claimsJws = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwtToken.stringify());
        return !claimsJws.getBody().getExpiration().before(new Date());
    }

    public Cookie createCookieWithRefreshToken(JwtToken jwtToken) {
        Cookie cookie = new Cookie(refreshTokenName, jwtToken.stringify());
        cookie.setHttpOnly(true);
        cookie.setMaxAge(jwtToken.isNotNull() ? refreshTokenValidityInMilliseconds : 0);
        cookie.setPath("/");
        cookie.setSecure(isCookieSecure);
        return cookie;
    }
}
