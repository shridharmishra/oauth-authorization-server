package com.shri.auth.authorizationserver.controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
/*@RequestMapping(path = "/oauth")*/
public class UserController {

    @GetMapping("/user")
    public Principal user(Principal principal) {
        System.out.println("Principal: " + principal);
        return principal;
    }

    @GetMapping("/test")
    public String test() {
        return "Test";
    }
}
