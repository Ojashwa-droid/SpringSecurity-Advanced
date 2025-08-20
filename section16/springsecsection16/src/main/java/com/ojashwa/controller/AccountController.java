package com.ojashwa.controller;

import com.ojashwa.model.Accounts;
import com.ojashwa.model.Customer;
import com.ojashwa.repository.AccountsRepository;
import com.ojashwa.repository.CustomerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequiredArgsConstructor
public class AccountController {
    private final AccountsRepository accountsRepository;
    private final CustomerRepository customerRepository;

    /**
     * This is a simple controller that handles one url and returns a simple String
     */

    @GetMapping("/myAccount")
    public Accounts getAccountDetails (@RequestParam String email) {
        Optional<Customer> optionalCustomer = customerRepository.findByEmail(email);
        if (optionalCustomer.isPresent()) {
            Accounts accounts = accountsRepository.findByCustomerId(optionalCustomer.get().getId());
            if (accounts != null) {
                return accounts;
            } else {
                return null;
            }
        }
        return null;
    }
}


