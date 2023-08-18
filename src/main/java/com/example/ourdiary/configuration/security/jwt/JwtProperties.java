package com.example.ourdiary.configuration.security.jwt;


import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@ConfigurationProperties(prefix = "ourdiary")
public class JwtProperties {
    private List<String> ignorePaths;
    private List<String> ignorePathsPost;

    public List<String> getIgnorePaths() {
        return ignorePaths;
    }

    public void setIgnorePaths(List<String> ignorePaths) {
        this.ignorePaths = ignorePaths;
    }

    public List<String> getIgnorePathsPost() {
        return ignorePathsPost;
    }

    public void setIgnorePathsPost(List<String> ignorePathsPost) {
        this.ignorePathsPost = ignorePathsPost;
    }
}
