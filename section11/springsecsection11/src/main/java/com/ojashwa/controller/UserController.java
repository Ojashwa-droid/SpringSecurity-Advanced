package com.ojashwa.controller;

import com.ojashwa.constants.ApplicationConstants;
import com.ojashwa.model.Customer;
import com.ojashwa.model.LoginRequestDTO;
import com.ojashwa.model.LoginResponseDTO;
import com.ojashwa.repository.CustomerRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.sql.Date;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
@Slf4j
public class UserController {

    private final CustomerRepository customerRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final Environment env;


    /**
     * API to register a new user.
     *
     * @param customer The information about the user to be registered. The
     *                 information should contain the name, email, mobile number,
     *                 password, role and created date.
     * @return The response entity containing the status of the operation. If the
     * operation is successful, the status will be 201 Created and the
     * body will contain the message "Given user details are successfully
     * registered". If the operation fails, the status will be 400 Bad
     * Request and the body will contain the message "User registration
     * failed".
     * @throws ResponseStatusException If the operation fails, an exception with
     *                                 the appropriate status code and the
     *                                 message will be thrown.
     */

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody Customer customer) {
        try {
            String hashPwd = passwordEncoder.encode(customer.getPwd());
            customer.setPwd(hashPwd);
            customer.setCreateDt(new Date(System.currentTimeMillis()));
            Customer savedCustomer = customerRepository.save(customer);

            if (savedCustomer.getId() > 0) {
                return ResponseEntity.status(HttpStatus.CREATED).
                        body("Given user details are successfully registered");
            } else {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).
                        body("User registration failed");
            }
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).
                    body("An exception occurred: " + ex.getMessage());
        }
    }

    @RequestMapping("/user")
    public Customer getUserDetailsAfterLogin(Authentication authentication) {
        Optional<Customer> optionalCustomer = customerRepository.findByEmail(authentication.getName());
        return optionalCustomer.orElse(null);
    }


    /**
     * This API endpoint is used to authenticate a user and return a JWT token.
     *
     * @param loginRequest The request body containing the username and password
     *                    of the user.
     * @return The response entity containing the status of the operation. If the
     * operation is successful, the status will be 200 OK and the body will
     * contain the JWT token. If the operation fails, the status will be 401
     * Unauthorized and the body will contain the message "Invalid username or
     * password".
     */

    @PostMapping("/apiLogin")
    public ResponseEntity<LoginResponseDTO> apiLogin(@RequestBody LoginRequestDTO loginRequest) {
        String jwt = "";
        Authentication authentication = UsernamePasswordAuthenticationToken
                .unauthenticated(loginRequest.username(), loginRequest.password());
        Authentication authenticationResponse = authenticationManager.authenticate(authentication);
        if (authenticationResponse != null && authenticationResponse.isAuthenticated()) {
            if (env != null){
                String secret = env.getProperty(ApplicationConstants.JWT_SECRET_KEY,
                        ApplicationConstants.JWT_SECRET_DEFAULT_VALUE);
                SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
                jwt = Jwts.builder().issuer("Ojas Bank").subject("Jwt Token")
                        .claim("username", authenticationResponse.getPrincipal())
                        .claim("authorities", authenticationResponse.getAuthorities().stream().map(
                                authority -> authority.getAuthority()).collect(Collectors.joining(",")))
                        .issuedAt((new java.util.Date()))
                        .expiration(new java.util.Date((new java.util.Date()).getTime() + 30000000))
                        .signWith(secretKey).compact();

            }
        }
        return ResponseEntity.status(HttpStatus.OK).header(ApplicationConstants.JWT_HEADER, jwt)
                .body(new LoginResponseDTO(HttpStatus.OK.getReasonPhrase(), jwt));
    }
}