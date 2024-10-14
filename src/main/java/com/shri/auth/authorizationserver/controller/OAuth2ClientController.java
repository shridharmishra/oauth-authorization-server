package com.shri.auth.authorizationserver.controller;

import com.shri.auth.authorizationserver.dto.OAuth2ClientDto;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/api/oauth2-clients")
public class OAuth2ClientController {

    private final RegisteredClientRepository clientRepository;

    public OAuth2ClientController(@Qualifier("registeredClientRepository") RegisteredClientRepository clientRepository) {
        this.clientRepository = clientRepository;
    }

    @PostMapping
    public ResponseEntity<String> addClient(@RequestBody OAuth2ClientDto clientDto) {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientDto.getClientId())
                .clientSecret("{noop}" + clientDto.getClientSecret())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scopes(scopes -> scopes.addAll(clientDto.getScopes()))
                .build();

        clientRepository.save(registeredClient);
        return ResponseEntity.ok("Client added successfully");
    }

}
