package com.erm.sociallogin.demo.security.oauth2;

import com.erm.sociallogin.demo.exception.OAuth2AuthenticationProcessingException;
import com.erm.sociallogin.demo.model.AuthProvider;
import com.erm.sociallogin.demo.model.User;
import com.erm.sociallogin.demo.repository.UserRepository;
import com.erm.sociallogin.demo.security.UserPrincipal;
import com.erm.sociallogin.demo.security.oauth2.user.OAuth2UserInfo;
import com.erm.sociallogin.demo.security.oauth2.user.OAuth2UserInfoFactory;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Optional;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    public CustomOAuth2UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    private User updateExistingUser(User existingUser, OAuth2UserInfo oAuth2UserInfo){
        existingUser.setEmail(oAuth2UserInfo.getName());
        existingUser.setImageUrl(oAuth2UserInfo.getImageUrl());
        return userRepository.save(existingUser);
    }

    private User registerNewUser(OAuth2UserRequest oAuth2UserRequest,
                                 OAuth2UserInfo oAuth2UserInfo){
        User user = new User();

        user.setProvider(AuthProvider.valueOf(oAuth2UserRequest.getClientRegistration().getRegistrationId()));
        user.setProviderId(oAuth2UserInfo.getId());
        user.setName(oAuth2UserInfo.getName());
        user.setEmail(oAuth2UserInfo.getEmail());
        user.setImageUrl(oAuth2UserInfo.getImageUrl());
        return userRepository.save(user);
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest request, OAuth2User oAuth2User){
        OAuth2UserInfo oAuth2UserInfo =
                OAuth2UserInfoFactory.getOAuth2UserInfo(
                        request.getClientRegistration().getRegistrationId(),
                        oAuth2User.getAttributes());

        if(StringUtils.isEmpty(oAuth2UserInfo.getEmail())){
            throw new OAuth2AuthenticationProcessingException("Email not found from OAuth2 " +
                    "provider");
        }

        Optional<User> byEmail = userRepository.findByEmail(oAuth2UserInfo.getEmail());
        User user;
        if(byEmail.isPresent()){
            user = byEmail.get();
            if(!user.getProvider().equals(AuthProvider.valueOf(
                    request.getClientRegistration().getRegistrationId()))){
                throw new OAuth2AuthenticationProcessingException("Looks like you're signed up " +
                        "with " + user.getProvider() + " account. Please use your " +
                        user.getProvider() + " account to login.");
            }
            user = updateExistingUser(user, oAuth2UserInfo);
        } else {
            user = registerNewUser(request, oAuth2UserInfo);
        }

        return UserPrincipal.create(user, oAuth2User.getAttributes());
    }

    public OAuth2User loadUser(OAuth2UserRequest request) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(request);

        try {
            return processOAuth2User(request, oAuth2User);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }
}
