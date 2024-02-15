package com.ohgiraffers.security.auth.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public class HeaderFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletResponse res = (HttpServletResponse) response;

        // 외부의 어떤 요청을 허용할 건인가
        res.setHeader("Access-Control-Allow-Origin", "*");
        res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE");
        res.setHeader("Access-Control-Max-Age", "3600");
        // 응답 헤더는 사전 요청에 대한 응답으로 사용
        res.setHeader("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, Authorization, X-XSRF-token");
        // 인증 정보를 포함할 수 있는지
        // 서버는 요청에 대해 인증 정보를 포함하지 않도록 설정
        res.setHeader("Access-Control-Allow-Credentials", "false");
        chain.doFilter(request, response);

    }
}
