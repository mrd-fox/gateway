package com.skillshub.gateway_service.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.boot.info.BuildProperties;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
public class StartupLogger {

    private static final Logger LOGGER = LoggerFactory.getLogger(StartupLogger.class);

    // 🧩 Injection du port à partir de la config active
    @Value("${server.port}")
    private String serverPort;

    private final BuildProperties buildProperties;

    public StartupLogger(BuildProperties buildProperties) {
        this.buildProperties = buildProperties;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onStartup() {
        String baseUrl = String.format("http://localhost:%s", serverPort);

        LOGGER.info("""
                
                ===============================================================
                
                    🚀  Gateway Service Started
                    Name:    {}
                    Version: {}
                    
                    Base URL:    {}
                    Routes URL:  {}/actuator/gateway/routes
                    Health URL:  {}/actuator/health
                
                ===============================================================
                """,
                buildProperties.getName(),
                buildProperties.getVersion(),
                baseUrl,
                baseUrl,
                baseUrl
        );    }
}

