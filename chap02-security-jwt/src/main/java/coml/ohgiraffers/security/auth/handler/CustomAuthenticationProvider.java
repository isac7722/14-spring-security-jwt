package coml.ohgiraffers.security.auth.handler;

import coml.ohgiraffers.security.auth.model.DetailsUser;
import coml.ohgiraffers.security.auth.service.DetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private DetailsService detailsService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;


    // 사용자 정보를 조회하고 조회한 결과를 비교하는 메소드
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 1. username password Token(사용자가 로그인 요청시 날린 아이디와 비밀번호를 가지고 있는 임시 객체)

        // authentication을 토큰 객체로 저장
        UsernamePasswordAuthenticationToken loginToken = (UsernamePasswordAuthenticationToken) authentication;

        String username = loginToken.getName();
        String password = (String) loginToken.getCredentials(); // Token이 가지고 있는 값, 비교할 수 있게끔 일반 변수로 저장

        // 2. DB에서 username에 해당하는 정보를 조회한다
        DetailsUser foundUser = (DetailsUser) detailsService.loadUserByUsername(username); // 부모 객체로 변환


        // 사용자가 입력한 username, password와  아이디와 비밀번호를 비교하는 로직을 수행함

        // encoding 된 DB의 pass랑 사용자가 입력한 encoding  안된 pass 비교 - 이것이 matches의 역할
        if (!passwordEncoder.matches(password, foundUser.getPassword())){
            throw new BadCredentialsException("password가 일치하지 않습니다.");
        }

        return new UsernamePasswordAuthenticationToken(foundUser, foundUser.getPassword(), foundUser.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {



        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
