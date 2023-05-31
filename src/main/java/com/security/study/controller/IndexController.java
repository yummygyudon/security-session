package com.security.study.controller;

import com.security.study.config.auth.PrincipalDetails;
import com.security.study.model.User;
import com.security.study.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequiredArgsConstructor
@Slf4j
public class IndexController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    /**
     * 일반 계정 대상으로만 가능
     * OAuth2 로그인을 통한 확인 불가능(Class Casting Exception 발생)
     */
    @GetMapping("/test/login")
    private @ResponseBody String loginTest(
            Authentication authentication,
            /**
             * 의존성 주입 ( Authentication 에는 UserDetails 객체만 저장 가능
             * ( PrincipalDetails 객체도 가능 :  UserDetails 구현체이기 때문에 )
             */
            @AuthenticationPrincipal PrincipalDetails userDetailsImpl,
            @AuthenticationPrincipal UserDetails userDetails) {
        log.info("===================== /test/login =====================");

        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        log.info("authentication : {}", principalDetails.getUser());

        log.info("userDetails : {}", userDetails.getUsername());
        log.info("PrincipalDetails : {}", userDetailsImpl.getUser());
        log.info("=======================================================");
        /*
        * authentication : User{id=1, username='jung', password='$2a$10$ZvVb4QeeuQGfA1XpaJvd3O9Uet3wunmA5pMKK.xfFBRkbjN2d0owG', email='bang2brew@gmail.com', role='ROLE_USER', createDate=2023-05-29 04:32:12.026}
        * userDetails : jung
        * PrincipalDetails : User{id=1, username='jung', password='$2a$10$ZvVb4QeeuQGfA1XpaJvd3O9Uet3wunmA5pMKK.xfFBRkbjN2d0owG', email='bang2brew@gmail.com', role='ROLE_USER', createDate=2023-05-29 04:32:12.026}
        * */
        return "일반 로그인 Test 완료";
    }

    @GetMapping("/test/oauth/login")
    private @ResponseBody String oauthLoginTest(
            Authentication authentication
            , @AuthenticationPrincipal OAuth2User oAuth2
    ) {
        log.info("===================== /test/oauth/login =====================");
        // OAuth2User 객체로 다운 캐스팅
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        log.info("authentication : {}", oAuth2User.getAttributes());

        log.info("OAuth2User : {}", oAuth2.getAttributes());
        log.info("=============================================================");
        /*
         * ===================== /test/oauth/login =====================
         * authentication : {sub=116641255216040627007, name=정동규, given_name=동규, family_name=정, picture=https://lh3.googleusercontent.com/a/AAcHTtfHMPXkjDzYMRSn65xoFGt8MTG5URKg3PbYjzC7=s96-c, email=bang2brew@gmail.com, email_verified=true, locale=ko}
         * =============================================================*
         * */
        return "Oauth2 로그인  완료";
    }

    @GetMapping({"", "/"})
    public String index() {
        /**
         * localhost:8080/
         * localhost:8080
         */
        // Mustache 템플릿 엔진 (단, Thymeleaf 가 훨씬 호환성 좋은 엔진
        return "index";
    }

    // UserDetails 이던 OAuth2User 이던 상관없이 로그인/회원가입 가능
    @GetMapping("/user")
    public @ResponseBody String user(
            @AuthenticationPrincipal PrincipalDetails principalDetails
    ) {
        log.info("principalDetails : {}", principalDetails.getUser());
        return "user";
    }

    @GetMapping("/admin")
    public @ResponseBody String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    public @ResponseBody String manager() {
        return "manager";
    }

    // SecurityConfig 설정 이전에는
    // 스프링 시큐리티에서 자체적으로 주소를 낚아채서 보내버림
    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinFrom() {
        return "joinForm";
    }

    @PostMapping("/join")
    public String join(User user) {
        log.info("Input User = {}", user);

        user.setRole("ROLE_USER");
        user.setPassword(
                bCryptPasswordEncoder.encode(user.getPassword())
        );
        userRepository.save(user);
        User savedUser = userRepository.findByUsername(user.getUsername());
        log.info("Saved User = {}", savedUser);
        return "redirect:/loginForm";
    }
//    @GetMapping("/joinProc")
//    public @ResponseBody String joinProc() {
//        return "회원가입 완료!";
//    }

    @Secured("ROLE_ADMIN") // 해당 어노테이션으로 간단하게
    /**
     * 글로벌 범위가 아닌
     * 한정적 범위로 .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')") 와 같은 기능을 사용하고 싶을 때 유용
     */
    @GetMapping("/info")
    public @ResponseBody String info() {
        return "개인정보";
    }

//    @PostAuthorize() :: 잘 사용되지 않는 메서드
    @PreAuthorize("hasAnyRole('ROLE_MANAGER', 'ROLE_ADMIN')")
    /**
     * 현재 이 메서드가 실행되기 직전에 실행
     */
    @GetMapping("/data")
    public @ResponseBody String data() {
        return "개인정보";
    }
}
