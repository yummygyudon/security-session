package com.security.study.config.auth;

import com.security.study.model.User;
import com.security.study.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * UserDetails 객체를 내포할 수 있는 Authentication 객체를 다루는 Service
 */

/**
 *  Security 에서 낚아챈 로그인 작업 시에 활용
 *  -> login 요청 시, 자동으로 UserDetailsService 타입으로 IoC 되어 있는
 *          loadUserByUsername 호출
 *
 *  [중요] Form에서의 input Value 명을 조심해야 한다
 *          -> 유동적으로 사용하려면 Config에서 `.usernameParameter("[formInputValueAttributeName]")`
 *
 * @see com.security.study.config.SecurityConfig
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    // Security Session 에 Authentication 객체 내부에 UserDetails 객체가 담겨 들어가게 됨.
    // Security Session( Authentication( UserDetails::PrincipalDetails ) )
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User loadedUserEntity = userRepository.findByUsername(username);
        log.info("loadedUser = {}",loadedUserEntity);
        if (loadedUserEntity != null) {
            return new PrincipalDetails(loadedUserEntity);
        }
        return null;
    }
}
