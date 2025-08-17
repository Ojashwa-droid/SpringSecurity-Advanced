package com.ojashwa.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class ProjectSecurityConfig {

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> requests.requestMatchers("/secure").authenticated()
                        .anyRequest().permitAll())
                .formLogin(Customizer.withDefaults())
                .oauth2Login(Customizer.withDefaults());
        return http.build();
    }
/*

    // We can set some properties related to client registration (clientId and clientSecret) in "application.properties" file.
    // That is going to work the same and behind the scenes that will create this bean for us.

    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
        ClientRegistration github = githubClientRegistration();
        ClientRegistration facebook = facebookClientRegistration();
        return new InMemoryClientRegistrationRepository(github, facebook);
    }

    private ClientRegistration githubClientRegistration() {
        ClientRegistration github = CommonOAuth2Provider.GITHUB.getBuilder("github").clientId("Ov23liy2hw98vDnwBSri")
                .clientSecret("1b2b146ea57c028705f690c37a9ff7a1d3e696f8").build();
        return github;
    }

    private ClientRegistration facebookClientRegistration() {
        ClientRegistration facebook = CommonOAuth2Provider.FACEBOOK.getBuilder("facebook").clientId("669428415615576")
                .clientSecret("038eac4674b1ced97d0399edfbe13de1").build();
        return facebook;
    }
*/

}
