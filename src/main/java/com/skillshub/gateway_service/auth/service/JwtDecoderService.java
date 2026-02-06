package com.skillshub.gateway_service.auth.service;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URL;
import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

/**
 * JwtDecoderService:
 * - Downloads public JWK from Keycloak
 * - Caches it
 * - Verifies signature of JWT
 * - Returns the decoded claims
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class JwtDecoderService {

    @Value("${spring.security.oauth2.client.provider.keycloak.issuer-uri}")
    private String issuerUri;

    private volatile JWKSet cachedJwkSet;
    private volatile Instant lastFetch = Instant.EPOCH;

    private static final long CACHE_DURATION_SECONDS = 300;

    public Map<String, Object> decodeJwt(String token) {

        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            JWKSet jwkSet = fetchJwkSet();

            JWK jwk = jwkSet.getKeyByKeyId(signedJWT.getHeader().getKeyID());
            if (jwk == null) {
                throw new IllegalStateException("No matching JWK key found in Keycloak JWK set");
            }

            RSAKey rsaKey = jwk.toRSAKey();
            JWSVerifier verifier = new RSASSAVerifier(rsaKey);

            if (!signedJWT.verify(verifier)) {
                throw new IllegalStateException("Invalid JWT signature");
            }

            Date exp = signedJWT.getJWTClaimsSet().getExpirationTime();
            if (exp != null && exp.before(new Date())) {
                throw new IllegalStateException("Expired JWT token");
            }

            String tokenIssuer = signedJWT.getJWTClaimsSet().getIssuer();
            if (tokenIssuer == null || !issuerUri.equals(tokenIssuer)) {
                throw new IllegalStateException("Invalid issuer: " + tokenIssuer);
            }

            return signedJWT.getJWTClaimsSet().getClaims();

        } catch (ParseException e) {
            throw new IllegalStateException("Malformed JWT token", e);
        } catch (IllegalStateException e) {
            // Preserve validation messages (Expired JWT token, Invalid issuer, etc.)
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("JWT processing error", e);
        }
    }

    private synchronized JWKSet fetchJwkSet() throws Exception {
        Instant now = Instant.now();

        if (cachedJwkSet != null &&
                lastFetch.plusSeconds(CACHE_DURATION_SECONDS).isAfter(now)) {
            return cachedJwkSet;
        }

        String jwkUri = issuerUri + "/protocol/openid-connect/certs";

        log.info("🔑 Fetching JWK keys from Keycloak: {}", jwkUri);
        cachedJwkSet = JWKSet.load(new URL(jwkUri));
        lastFetch = now;

        return cachedJwkSet;
    }
}