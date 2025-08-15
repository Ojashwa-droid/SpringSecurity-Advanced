package com.ojashwa.filter;

import com.ojashwa.constants.ApplicationConstants;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.stream.Collectors;

public class JwtTokenGeneratorFilter extends OncePerRequestFilter {
    /**
     * This filter is used to generate a jwt-token in the response header of the login endpoint, after the user has been
     * successfully authenticated.
     * <p>
     * The filter is executed only when the request is for the login endpoint, as determined by the
     * {@link #shouldNotFilter} method.
     * </p>
     * <p>
     * The filter gets the authentication object from the security context, checks if it is not null, and then uses the
     * application properties to generate the jwt-token with the {@link SignatureAlgorithm#HS256} algorithm.
     * </p>
     * <p>
     * The filter then adds the jwt-token to the response header as the value of the "Authorization" header, prefixed with
     * "Bearer ".
     * </p>
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            Environment env = getEnvironment();
            if (env != null) {
                String secret = env.getProperty(ApplicationConstants.JWT_SECRET_KEY,
                        ApplicationConstants.JWT_SECRET_DEFAULT_VALUE);
                SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
                String jwt = Jwts.builder().issuer("Ojas Bank").subject("Jwt Token")
                        .claim("username", authentication.getName())
                        .claim("authorities", authentication.getAuthorities().stream().map(
                                authority -> authority.getAuthority()).collect(Collectors.joining(",")))
                        .issuedAt(new Date())
                        .expiration(new Date((new Date()).getTime() + 30000000))
                        .signWith(secretKey).compact();

                response.setHeader(ApplicationConstants.JWT_HEADER, jwt);
            }
        }
        filterChain.doFilter(request, response);
    }


    /**
     * This method is used to determine whether or not the filter should be executed, based on the current request.
     * <p>
     * If the request is for the login endpoint, the filter should be executed to generate a jwt-token.
     * <p>
     * If the request is not for the login endpoint, the filter should not be executed.
     * </p>
     * <p>
     *     If this method returns false, the filter is going to be executed.
     *     If true, the filter will not be executed.
     *     We want to generate our jwt-token only during login, so it fits right with our business requirement.
     * </p>
     *
     * @param request The current HTTP request
     * @return false if the filter should be executed, true if the filter should not be executed
     * @throws ServletException
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return !request.getServletPath().equals("/user");
    }
}