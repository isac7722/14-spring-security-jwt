package com.ohgiraffers.security.auth.filter;

import com.ohgiraffers.security.auth.model.DetailsUser;
import com.ohgiraffers.security.common.AuthConstants;
import com.ohgiraffers.security.common.utils.TokenUtils;
import com.ohgiraffers.security.user.entity.User;
import com.ohgiraffers.security.user.model.OhgiraffersRole;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {


    public JwtAuthorizationFilter(AuthenticationManager authenticationManager){
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        /* 권한이 필요없는 리소스 */
        List<String> roleLessList = Arrays.asList(
                "/signup"
        );

        // 권한이 필요 없는 요청이 들어왔는지 확인한다
        if (roleLessList.contains(request.getRequestURI())){
            chain.doFilter(request, response);
            return;
        }

        String header = request.getHeader(AuthConstants.AUTH_HEADER);
        System.out.println("문제");
        try {
            // header가 존재하는 경우
            if (header != null && !header.equalsIgnoreCase("")){
                String token = TokenUtils.splitHeader(header);

                // token 유효성 체크
                if (TokenUtils.isValidToken(token)){
                    // token 복호화 claim 받아옴
                    Claims claims = TokenUtils.getClaimsFormToken(token);

                    // detail 객체 만듬 밑에 필요하기 때문
                    DetailsUser authentication = new DetailsUser();
                    User user = new User();
                    user.setUserId(claims.get("userId").toString());

                    // 사용자의 Role enum객체를 주입
                    user.setRole(OhgiraffersRole.valueOf(claims.get("Role").toString()));
                    authentication.setUser(user);

                    // 필요한 정보만 담아서 token에 넣어줌

                    AbstractAuthenticationToken authenticationToken = UsernamePasswordAuthenticationToken.
                            authenticated(authentication, token, authentication.getAuthorities());
                    authenticationToken.setDetails(new WebAuthenticationDetails(request));

                    // token 을 contextHolder에 담아줌
                    // 인증 로직을 처리하기 위해 securityContextHolder 에 담는것
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);

                    // 인증 확인하는 로직은 security에서 알아서 처리
                    chain.doFilter(request, response);
                }else {
                    throw new RuntimeException("토큰이 유효하지 않습니다.");
                }
            }else {
                throw new RuntimeException("토큰이 존재하지 않습니다.");
            }
        }catch (Exception e){
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            PrintWriter printWriter = response.getWriter();
            JSONObject jsonObject = jsonResponseWrapper(e);
            printWriter.println(jsonObject);
            printWriter.flush();
            printWriter.close();
        }



    }

    private JSONObject jsonResponseWrapper(Exception e){

        String resultMsg = "";
        if (e instanceof ExpiredJwtException){
            resultMsg = "Token Expired";
        } else if (e instanceof SignatureException) {
            resultMsg = "Token SignatureException login";
        }else if (e instanceof JwtException){
            resultMsg = "Token parsing JwtException";
        }else {
            resultMsg = "Other token Error";
        }

        HashMap<String, Object> jsonMap = new HashMap<>();
        jsonMap.put("status", 401);
        jsonMap.put("message", resultMsg);
        jsonMap.put("reason", e.getMessage());
        JSONObject jsonObject = new JSONObject(jsonMap);
        return jsonObject;
    }



}
