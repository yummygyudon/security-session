package com.security.study.config.auth;

import com.security.study.model.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

/**
 * Security 가 "/login" 주소 요청에 대해 낚아채서 로그인 작업을 진행
 * -> 로그인 완료 시, Session 생성 (Security Session -> Security ContextHolder 영역에 저장)
 *
 * 단, 해당 세션(Security Session)에 들어갈 수 있는 객체 타입은 제한적
 * - Authentication 타입 객체
 *      - 해당 객체에 저장되어 있는 User 정보 객체 타입도 제한적
 *      - UserDetails 타입 객체
 */
// Authentication 객체 내부에 저장할 수 있는 User 정보 객체 구현
@Data
public class PrincipalDetails implements UserDetails, OAuth2User {
    private User user; // 컴포지션
    private Map<String, Object> attributes;

    // 일반 로그인 때 사용하는 생성자
    public PrincipalDetails(User user) {
        this.user = user;
    }

    // OAuth2 로그인 때 사용하는 생성자
    public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    // 해당 User의 권한 Return
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();
        collection.add(
                (GrantedAuthority) () -> user.getRole()
        );
        return collection;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    // 해당 계정 기한 초과 여부
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 해당 계정이 잠겨있는지
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 해당 계정 비밀번호 기한 초과 여부
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 해당 계정 사용 여부
    @Override
    public boolean isEnabled() {
        /**
         * 휴면 계정으로 전환하기로 결정되었을 때
         */
        return true;
    }

    @Override
    public String getName() {
        return null;
    }
}
