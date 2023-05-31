package com.security.study.config.oauth;

import com.security.study.config.auth.PrincipalDetails;
import com.security.study.config.oauth.provider.FacebookUserInfo;
import com.security.study.config.oauth.provider.GoogleUserInfo;
import com.security.study.config.oauth.provider.NaverUserInfo;
import com.security.study.config.oauth.provider.OAuth2UserInfo;
import com.security.study.model.User;
import com.security.study.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.ModelAttribute;

import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;

    /**
     * 구글로부터 받은 userRequest 데이터에 대한 후처리 함수
     */
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        /*
        userRequest.ClientRegistration : ClientRegistration{
                                                registrationId='google',
                                                clientId='627649091571-3bvuj4nhcrvdcp68juij256ah9gkqt1m.apps.googleusercontent.com',
                                                clientSecret='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',
                                                clientAuthenticationMethod=org.springframework.security.oauth2.core.ClientAuthenticationMethod@4fcef9d3,
                                                authorizationGrantType=org.springframework.security.oauth2.core.AuthorizationGrantType@5da5e9f3,
                                                redirectUri='{baseUrl}/{action}/oauth2/code/{registrationId}',
                                                scopes=[email, profile],
                                                providerDetails=org.springframework.security.oauth2.client.registration.ClientRegistration$ProviderDetails@1f77a5de,
                                                clientName='Google'
                                        }

        userRequest.AccessToken : org.springframework.security.oauth2.core.OAuth2AccessToken@bb568c9c

        userRequest.RedirectUri: {baseUrl}/{action}/oauth2/code/{registrationId}

        loadUser(userRequest) : {
                sub=116641255216040627007,
                name=정동규,
                given_name=동규,
                family_name=정,
                picture=https://lh3.googleusercontent.com/a/AAcHTtfHMPXkjDzYMRSn65xoFGt8MTG5URKg3PbYjzC7=s96-c,
                email=bang2brew@gmail.com,
                email_verified=true,
                locale=ko
        }
         */
        log.info("userRequest.ClientRegistration : {}", userRequest.getClientRegistration());
        log.info("userRequest.AccessToken Value : {}", userRequest.getAccessToken().getTokenValue());
        log.info("userRequest.RedirectUri: {}", userRequest.getClientRegistration().getRedirectUri());
        log.info("loadUser(userRequest) : {}", super.loadUser(userRequest).getAttributes());

        OAuth2User oAuth2User = super.loadUser(userRequest);

        String provider = userRequest.getClientRegistration().getRegistrationId();
        OAuth2UserInfo oAuth2UserInfo = null;

        if (provider.equalsIgnoreCase("google")) {
            log.info("=== Google Login Request ===");
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (provider.equalsIgnoreCase("facebook")) {
            log.info("=== Facebook Login Request ===");
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        } else if (provider.equalsIgnoreCase("naver")) {
            log.info("=== Naver Login Request ===");
            // application.yml 에 user-name-attribute: response 로 등록했기 때문에
            // response를 attributes로 잘 인식해서 JSON -> Map 객체가 넘어옴
            oAuth2UserInfo = new NaverUserInfo((Map)oAuth2User.getAttributes().get("response"));
        } else {
            log.info("=== 알 수 없는 로그인 수단 ===");
        }
        assert oAuth2UserInfo != null;
        String providerId = oAuth2UserInfo.getProviderId();
        String name = provider + "_" + providerId; // google_(providerId)
        String email = oAuth2UserInfo.getEmail();
        String password = bCryptPasswordEncoder.encode(name + email);
        String role = "ROLE_USER";

        User userEntity = userRepository.findByUsername(name);
        if (userEntity == null) {
            log.info("최초 OAuth 로그인");
            userEntity = User.builder()
                    .username(name)
                    .password(password)
                    .email(email)
                    .role(role)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            userRepository.save(userEntity);
        } else {
            log.info("이전에 OAuth 로그인 이력 존재");
        }

        /**
         * 다중 구현 -> OAuth2User 반환 타입에 반환 문제 X
         *
         * -> PrincipalDetails Authentication 에 저장
         */
        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }
}
