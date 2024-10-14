package com.shri.auth.authorizationserver.config;

import com.shri.auth.authorizationserver.entity.OAuth2Client;
import com.shri.auth.authorizationserver.repository.OAuth2ClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.HashSet;
import java.util.stream.Collectors;


public class DatabaseRegisteredClientRepository implements RegisteredClientRepository {

    private final OAuth2ClientRepository repository;

    public DatabaseRegisteredClientRepository(OAuth2ClientRepository repository) {
        this.repository = repository;
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        OAuth2Client client = toEntity(registeredClient);
        repository.save(client);
    }

    @Override
    public RegisteredClient findById(String id) {
        return repository.findById(id)
                .map(this::toRegisteredClient)
                .orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return repository.findById(clientId)
                .map(this::toRegisteredClient)
                .orElse(null);
    }

    private OAuth2Client toEntity(RegisteredClient registeredClient) {
        OAuth2Client client = new OAuth2Client();
        client.setClientId(registeredClient.getClientId());
        client.setClientSecret(registeredClient.getClientSecret());
        client.setClientAuthenticationMethods(registeredClient.getClientAuthenticationMethods().stream()
                .map(ClientAuthenticationMethod::getValue)
                .collect(Collectors.toSet()));
        client.setAuthorizationGrantTypes(registeredClient.getAuthorizationGrantTypes().stream()
                .map(AuthorizationGrantType::getValue)
                .collect(Collectors.toSet()));
        client.setScopes(new HashSet<>(registeredClient.getScopes()));
        return client;
    }

    private RegisteredClient toRegisteredClient(OAuth2Client client) {
        return RegisteredClient.withId(client.getClientId())
                .clientId(client.getClientId())
                .clientSecret(client.getClientSecret())
                .clientAuthenticationMethods(methods -> client.getClientAuthenticationMethods().forEach(method ->
                        methods.add(new ClientAuthenticationMethod(method))))
                .authorizationGrantTypes(types -> client.getAuthorizationGrantTypes().forEach(type ->
                        types.add(new AuthorizationGrantType(type))))
                .scopes(scopes -> scopes.addAll(client.getScopes()))
                .build();
    }
}