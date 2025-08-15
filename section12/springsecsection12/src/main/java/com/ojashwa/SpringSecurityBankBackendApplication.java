package com.ojashwa;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
/**
 * Completely optional to use these annotations within spring-boot environment,
 * it was required in spring-core-framework.
 *
 * @EnableWebSecurity
 * @EnableJpaRepositories("com.ojashwa.repository")
 * @EntityScan("com.ojashwa.model")
 */
public class SpringSecurityBankBackendApplication {
    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityBankBackendApplication.class, args);
    }
}