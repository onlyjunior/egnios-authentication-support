package com.egnios.authentication.config.auth.firebase;

import com.egnios.authentication.service.IFirebaseService;
import com.google.firebase.auth.FirebaseAuthException;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class FirebaseFilter extends OncePerRequestFilter {

    private static String HEADER_NAME = "X-Authorization-Firebase";
    private static final Logger logger = LoggerFactory.getLogger(FirebaseFilter.class);

    private IFirebaseService firebaseService;

    public FirebaseFilter(IFirebaseService firebaseService) {
        this.firebaseService = firebaseService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {

        String xAuth = request.getHeader(HEADER_NAME);
        if (StringUtils.isBlank(xAuth)) {
            SecurityContextHolder.getContext().setAuthentication(null);
            filterChain.doFilter(request, response);
            logger.error("token empty!!");
        } else {

            try {
                FirebaseTokenHolder holder = firebaseService.parseToken(xAuth);
                String userName = holder.getUid();

                Authentication auth = new FirebaseAuthenticationToken(userName, holder);
                SecurityContextHolder.getContext().setAuthentication(auth);

                filterChain.doFilter(request, response);
            } catch (FirebaseAuthException e) {
                SecurityContextHolder.getContext().setAuthentication(null);
                logger.warn("Unauthorized: {}", e.getErrorCode());
                filterChain.doFilter(request, response);
            } catch (IllegalArgumentException e) {
                throw new SecurityException(e.getMessage());
            }
        }
    }

}
