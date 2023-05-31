package com.cos.securityex01.controller;

import java.util.Iterator;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.cos.securityex01.config.auth.PrincipalDetails;
import com.cos.securityex01.model.User;
import com.cos.securityex01.repository.UserRepository;

@Controller
@RequiredArgsConstructor
@Slf4j
// 일반 Controller이기 떄문에 View 리턴
public class IndexController {
	private final BCryptPasswordEncoder bCryptPasswordEncoder;
	private final UserRepository userRepository;


	// {localhost:8080/, localhost:8080}
	@GetMapping({ "", "/" })
	public @ResponseBody String index() {
		// Mustache -> 기본 폴더 : src/main/resources/ 로 잡힙
		// ViewResolver 설정 : `templates`(prefix), `.mustache`(suffix)
		/**
		 * return "index";
		 * -> src/main/resources/templates/index.mustache
		 *  ( Mustache 기본 Path)+Prefix + (return value) + Suffix
		 *
		 * -> WebMvcConfig 에서 재설정
		 */

		return "인덱스 페이지입니다.";
	}


	@GetMapping("/user")
	public @ResponseBody String user(
			@AuthenticationPrincipal PrincipalDetails principal
	) {
		log.info("Principal : {}", principal);
		log.info("OAuth2 : {}", principal.getUser().getProvider());

		// iterator 순차 출력 해보기
		Iterator<? extends GrantedAuthority> iter = principal.getAuthorities().iterator();
		while (iter.hasNext()) {
			GrantedAuthority auth = iter.next();
			System.out.println(auth.getAuthority());
		}

		return "유저 페이지입니다.";
	}

	@GetMapping("/admin")
	public @ResponseBody String admin() {
		return "어드민 페이지입니다.";
	}
	
	//@PostAuthorize("hasRole('ROLE_MANAGER')")
	//@PreAuthorize("hasRole('ROLE_MANAGER')")
	@Secured("ROLE_MANAGER")
	@GetMapping("/manager")
	public @ResponseBody String manager() {
		return "매니저 페이지입니다.";
	}

	@GetMapping("/login")
	public String login() {
		return "login";
	}

	@PostMapping("/join")
	public String join(User user){
		log.info("@PostMapping - IndexController.join 실행");
		System.out.println(user);
		String rawPassword = user.getPassword();
		String encPassword = bCryptPasswordEncoder.encode(rawPassword);

		user.setPassword(encPassword);
		user.setRole("ROLE_USER");
		// 패스워드가 암호화되지 않아있으면 시큐리티로 로그인 불가
		userRepository.save(user);
		return "redirect:/";
	}
	@GetMapping("/join")
	public String join() {
		return "join";
	}

	//
	@PostMapping("/joinProc")
	public String joinProc(User user) {
		System.out.println("회원가입 진행 : " + user);
		String rawPassword = user.getPassword();
		String encPassword = bCryptPasswordEncoder.encode(rawPassword);
		user.setPassword(encPassword);
		user.setRole("ROLE_USER");
		userRepository.save(user);
		return "redirect:/";
	}
}
