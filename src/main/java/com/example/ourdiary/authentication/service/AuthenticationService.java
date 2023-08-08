package com.example.ourdiary.authentication.service;

import com.example.ourdiary.authentication.domain.JwtTokens;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface AuthenticationService {
    JwtTokens issueTokens(String username, String password);
    void login(String username, String password, HttpServletResponse response);
    void logout(HttpServletRequest request, HttpServletResponse response);
    void refresh(HttpServletRequest request, HttpServletResponse response);

}
