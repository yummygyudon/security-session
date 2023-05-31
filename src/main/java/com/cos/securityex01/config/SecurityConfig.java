package com.cos.securityex01.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.cos.securityex01.config.oauth.PrincipalOauth2UserService;

@Configuration // IoC 빈(bean)을 등록
/*
	@EnableWebSecurity // 스프링 시큐리 필터가 스프링 필터 체에 등록

	- extends WebSecurityConfigurerAdapter
*/
@EnableWebSecurity // 스프링 시큐리 필터가 스프링 필터 체에 등록
@RequiredArgsConstructor
public class SecurityConfig  {

	private final PrincipalOauth2UserService principalOauth2UserService;

	@Bean
	public BCryptPasswordEncoder encodePwd() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.csrf().disable();
		http.authorizeRequests()
				.antMatchers("/user/**").authenticated()
				// .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN') or
				// hasRole('ROLE_USER')")
				// .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN') and
				// hasRole('ROLE_USER')")
				.antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
				.anyRequest().permitAll()
				.and()
				.formLogin()
				.loginPage("/login")

				// login 주소가 호출되면 시큐리티가 낚아채서 대신 로그인 진행
				.loginProcessingUrl("/loginProc")
				.defaultSuccessUrl("/")
				.and()
				.oauth2Login()
				.loginPage("/login")
				.userInfoEndpoint()
				.userService(principalOauth2UserService);

		return http.build();
	}

//	@Override
//	protected void configure(HttpSecurity http) throws Exception {
//		http.csrf().disable();
//		http.authorizeRequests()
//				.antMatchers("/user/**").authenticated()
//				.antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
//				.antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
//				.anyRequest().permitAll();
//
////		super.configure(http);
//	}
}
