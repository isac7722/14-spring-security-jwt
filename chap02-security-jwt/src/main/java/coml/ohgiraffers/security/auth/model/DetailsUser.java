package coml.ohgiraffers.security.auth.model;

import coml.ohgiraffers.security.user.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Optional;

public class DetailsUser implements UserDetails {

    private User user;

    public DetailsUser() {
    }

    public DetailsUser(Optional<User> user) {
        // 에러를 방지하기 위해서 Optional
        // Optional에 있는 데이터는 get으로 받아온다
        this.user = user.get();
    }


    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        Collection<GrantedAuthority> authorities = new ArrayList<>();
        user.getRoleList().forEach(role -> authorities.add(()->role));

        return authorities;
    }

    @Override
    public String getPassword() {
        return user.getUserPass();
    }

    @Override
    public String getUsername() {
        return user.getUserId();
    }

    /*
    * 계정 만료 여부를 표현하는 메서드
    * false이면 해당 계정을 사용할 수 없다
    * */

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /*
    * 잠겨있는 계정을 확인하는 메스드
    * false이면 해당 계정을 사용할 수 없다
    *
    * 비밀번호 반복 실패로 일시적인 계정 lock의 경우
    * 혹은 오랜 기간 비 접속으로 휴면 처리
    * */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /*
    * 탈퇴 계정 여부를 표현하는 메서드
    * false면 사용불가능
    *
    * 보통 데이터 삭제는 즉시하는 것이 아닌 일정 기간 보관후 삭제
    * */

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /*
    * 계정 비활성화 여부로 사용자가 사용할 수 없는 상태
    * false면 계정 사용 불가
    *
    * 삭제 처리 같은 경우
    * */

    @Override
    public boolean isEnabled() {
        return true;
    }
}
