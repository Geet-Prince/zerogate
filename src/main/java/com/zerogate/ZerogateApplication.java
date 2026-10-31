// src/main/java/com/zerogate/ZerogateApplication.java
package com.zerogate;

import com.zerogate.filter.ZeroTrustGatewayFilter;
import com.zerogate.security.CryptoAndJwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@SpringBootApplication
@RestController
public class ZerogateApplication {
    private final CryptoAndJwtUtil cryptoUtil;
    private final ZeroTrustGatewayFilter gatewayFilter;

    public ZerogateApplication(CryptoAndJwtUtil cryptoUtil, ZeroTrustGatewayFilter gatewayFilter) {
        this.cryptoUtil = cryptoUtil;
        this.gatewayFilter = gatewayFilter;
    }

    public static void main(String[] args) {
        SpringApplication.run(ZerogateApplication.class, args);
    }

    @PostMapping("/auth/token")
    public Map<String, String> issueToken(
            @RequestParam(defaultValue = "prince") String user,
            @RequestParam(defaultValue = "ADMIN") String role) {
        return Map.of(
            "user", user,
            "role", role.toUpperCase(),
            "token", cryptoUtil.generateToken(user, role)
        );
    }

    @GetMapping("/api/v1/courses")
    public Map<String, Object> getCourses(HttpServletRequest req) {
        return Map.of(
            "service", "Downstream-Course-Service",
            "zeroTrustVerified", true,
            "authenticatedUser", req.getAttribute("X-Authenticated-User"),
            "role", req.getAttribute("X-Authenticated-Role"),
            "X-ZeroTrust-Signature", req.getAttribute("X-ZeroTrust-Signature"),
            "courses", List.of("CS301-Computer-Networks", "CS302-Operating-Systems", "CS303-Zero-Trust-Security")
        );
    }

    @PostMapping("/api/v1/grades")
    public Map<String, Object> updateGrades(HttpServletRequest req) {
        return Map.of(
            "service", "Downstream-Grade-Mutation-Service",
            "status", "GRADE_COMMITTED",
            "authorizedBy", req.getAttribute("X-Authenticated-User"),
            "X-ZeroTrust-Signature", req.getAttribute("X-ZeroTrust-Signature")
        );
    }

    @GetMapping("/admin/telemetry")
    public Map<String, Object> telemetry() {
        return gatewayFilter.getTelemetry();
    }
}
