package com.cos.securityex01.config.auth;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import com.cos.securityex01.model.User;

import lombok.Data;

// 시큐리티 /login 주소 요청이 오면 낚아채서 로그인을 진행시킨다.
// 로그인을 진행이 완료가 되면 security session 을 만들어준다. (Security ContextHolder)
// 오브젝트 -> Authentication 객체 (User 정보)

// User 타입 -> UserDetails 타입 객체
// Security Session => Authentication => UserDetails(PrincipleDetails)

// 	Authentication 객체에 저장할 수 있는 유일한 타입
public class PrincipalDetails implements UserDetails, OAuth2User{

	private static final long serialVersionUID = 1L;
	private User user;
	private Map<String, Object> attributes;

	// 일반 시큐리티 로그인시 사용
	public PrincipalDetails(User user) {
		this.user = user;
	}
	
	// OAuth2.0 로그인시 사용
	public PrincipalDetails(User user, Map<String, Object> attributes) {
		this.user = user;
		this.attributes = attributes;
	}

	// 해당 User 의 권한을 리턴하는 메서드
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		Collection<GrantedAuthority> collet = new ArrayList<GrantedAuthority>();

		collet.add((GrantedAuthority) () -> user.getRole());
//		collet.add(()->{ return user.getRole();});


		return collet;
	}

	public User getUser() {
		return user;
	}

	@Override
	public String getPassword() {
		return user.getPassword();
	}

	@Override
	public String getUsername() {
		return user.getUsername();
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		// 휴면 계정
		return true;
	}


	// 리소스 서버로 부터 받는 회원정보
	@Override
	public Map<String, Object> getAttributes() {
		return attributes;
	}

	// User의 PrimaryKey
	@Override
	public String getName() {
		return user.getId()+"";
	}
	
}
