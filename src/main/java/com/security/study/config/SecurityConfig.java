package com.security.study.config;

import com.security.study.config.oauth.PrincipalOauth2UserService;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity // -> Spring Security " Filter "가 "Spring Filter Chain" 에 등록
/**
 * securedEnabled = true :: secured 어노테이션을 활성화하기 위해 등록
 * prePostEnabled = true :: preAuthorize & postAuthorize 어노테이션을 활성화하기 위해 등록
 */
@EnableGlobalMethodSecurity(
        securedEnabled = true
        , prePostEnabled = true
)
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter { //deprecated 된 인터페이스

    private final PrincipalOauth2UserService principalOauth2UserService;

    // BCryptPasswordEncoder 빈 등록

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests()
                /**
                 * USER  대해서는 ROLE 상관없이 Access 허용
                 */
                .antMatchers("/user/**").authenticated() // "인증이 필요하다" 라는 것을 설정
                /**
                 * MANAGER 대해서는 ADMIN & MANAGER 만 Access 허용
                 */
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                /**
                 * ADMIN
                 */
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                // 그 외 나머지 URL 모두 반영
                .anyRequest().permitAll()
                // 설정 추가
                .and()
                /**
                 * 위 제약에 필요한 권한이 확인되지 않은 접근일 경우
                 * formLogin으로 무조건 이동
                 * .loginPage() 로 로그인View 지정
                 */
                .formLogin()
                .loginPage("/loginForm")
                // Form에서 input 태그 이름을 username이 아닌 다른 이름을 쓰고 싶다면
                // UserDetailsService에서 인식할 수 있도록 명시 필요
//                .usernameParameter("[Form sername 값 Input 태그 속성명]")

                /**
                 * login 주소 호출 시,
                 * 시큐리티가 낚아채서 대신 로그인 작업 진행
                 */
                .loginProcessingUrl("/login")
                /**
                 * 작업 성공 시, 자동으로 Mapping 해주는 URL
                 *
                 * 특징
                 * - 처음에 요청했었던 URL로 Redirect까지 해줌
                 *   (ex. /manager 로 요청했다가 login으로 넘어왔을 경우, 인증 완료 및 로그인 완료 시 다시 /manager 로 Redirect)
                 *   ( 위 예시처럼 redirect 했는데 해당 url에 접속 권한이 없는 계정일 경우 403 Forbidden 에러 발생 )
                 */
                .defaultSuccessUrl("/")

                .and()
                .oauth2Login()
                .loginPage("/loginForm")

                /**
                 * Google 로그인 이후 후처리 필요
                 * 1. 인가 코드 받기 (인증)
                 * 2. Access Token 받기 (권한)
                 * 3. 사용자 Profile 받기
                 * 4. 로그인 혹은 회원가입 자동으로 시켜주기
                 * * 로그인 완료 시, "토큰 + 사용자 정보" 한방에 받음
                 */
                .userInfoEndpoint()
                .userService(principalOauth2UserService)
        ;
    }
}
