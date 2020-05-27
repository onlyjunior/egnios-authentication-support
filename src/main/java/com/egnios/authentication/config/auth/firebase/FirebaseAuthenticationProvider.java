package com.egnios.authentication.config.auth.firebase;

import com.egnios.authentication.model.domain.Role;
import com.egnios.authentication.service.IFirebaseService;
import com.google.firebase.auth.UserRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class FirebaseAuthenticationProvider implements AuthenticationProvider {
    private static final Logger logger = LoggerFactory.getLogger(FirebaseAuthenticationProvider.class);

    @Autowired
    private IFirebaseService firebaseService;

    public boolean supports(Class<?> authentication) {
        return (FirebaseAuthenticationToken.class.isAssignableFrom(authentication));
    }

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }

        FirebaseAuthenticationToken authenticationToken = (FirebaseAuthenticationToken) authentication;
        String email = ((FirebaseTokenHolder) authenticationToken.getCredentials()).getEmail();
        Optional<UserRecord> user = firebaseService.findByEmailName(email);

        if (!user.isPresent()) {
            logger.warn("user {} not exist", email);
            return null;
        } else if (user.get().isDisabled()) {
            logger.warn("user {} is disabled", email);
            return null;
        }

//        Collection<GrantedAuthority> grantedAuthorities = user.get().getRoles().stream()
//            .map(r -> new SimpleGrantedAuthority(r.name()))
//            .collect(Collectors.toList());

        // TODO: get proper user roles from db
        Collection<GrantedAuthority> grantedAuthorities = Stream.of(Role.values())
                .map(r -> new SimpleGrantedAuthority(r.name())).collect(Collectors.toList());

        return new FirebaseAuthenticationToken(authenticationToken.getPrincipal(), authentication.getCredentials(),
            grantedAuthorities);
    }

}
