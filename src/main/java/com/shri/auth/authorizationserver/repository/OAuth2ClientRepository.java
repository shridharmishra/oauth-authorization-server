package com.shri.auth.authorizationserver.repository;

import com.shri.auth.authorizationserver.entity.OAuth2Client;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuth2ClientRepository extends JpaRepository<OAuth2Client, String> {
}
