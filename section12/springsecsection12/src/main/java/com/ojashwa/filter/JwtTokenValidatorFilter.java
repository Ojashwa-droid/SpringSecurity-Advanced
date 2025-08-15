package com.ojashwa.filter;

import com.ojashwa.constants.ApplicationConstants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class JwtTokenValidatorFilter extends OncePerRequestFilter {
    /**
     * This custom filter {@link JwtTokenValidatorFilter} is used to validate the JWT token at each request. If the
     * token is invalid, it will throw a {@link org.springframework.security.authentication.BadCredentialsException}
     * which will be handle by the {@link com.ojashwa.exceptionhandling.CustomAccessDeniedHandler} class
     * <p>
     * The filter is configured to not be executed if the request is to the "/user" path.
     * </p>
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

      /* This was just for validating and testing why my "/apiLogin" end point was getting intercepted stuck in this filter.
      Now the problem has been resolved.
      The issue was with the filter chaining, which I had done inside the if block and not outside of it.

       String requestURI = request.getRequestURI();
        if ("/apiLogin".equals(requestURI) && "POST".equalsIgnoreCase(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }
      */

        String jwt = request.getHeader(ApplicationConstants.JWT_HEADER);
        if (jwt != null && jwt.startsWith("Bearer ")) {
            jwt = jwt.substring("Bearer ".length());
            try {
                Environment env = getEnvironment();
                if (env != null) {
                    String secret = env.getProperty(ApplicationConstants.JWT_SECRET_KEY,
                            ApplicationConstants.JWT_SECRET_DEFAULT_VALUE);
                    SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
                    if (secretKey != null) {
                        Claims claims = Jwts.parser().verifyWith(secretKey)
                                .build().parseSignedClaims(jwt).getPayload();
                        String username = String.valueOf(claims.get("username"));
                        String authorities = String.valueOf(claims.get("authorities"));
                        Authentication authentication = new UsernamePasswordAuthenticationToken(username, null,
                                AuthorityUtils.commaSeparatedStringToAuthorityList(authorities)); // This can also be done via Streams API
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                }
            }catch (Exception exception) {
                throw new BadCredentialsException("Invalid JWT token received");
            }
        }
        filterChain.doFilter(request, response);
    }


    /**
     * This method is used to determine if the filter should be executed or not at each request.
     * If this method returns true, the filter will not be executed.
     * The filter is configured to not be executed if the request is to the "/user" path.
     *
     * @param request The request to process
     * @return true if the filter should be executed or false if it should not
     * @throws ServletException
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getServletPath().equals("/user");
    }
}