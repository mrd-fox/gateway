package com.skillshub.gateway_service.auth;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;


@ConfigurationProperties(prefix = "skillshub.auth")
@Getter
@Setter
public class AuthCookieProperties {

    private String cookieName;
    private String cookieDomain;
    private boolean cookieSecure;
    private String cookieSameSite;
    private long cookieMaxAge;
    private String redirectAfterLogin;
    private String redirectAfterLogout;

}