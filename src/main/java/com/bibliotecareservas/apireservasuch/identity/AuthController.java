package com.bibliotecareservas.apireservasuch.identity;

import java.time.Instant;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import com.bibliotecareservas.apireservasuch.catalog.CatalogRepository;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    public record LoginRequest(@NotBlank @Pattern(regexp="[0-9]{8}") String dni,
                               @NotBlank @Size(max=72) String password) {}
    public record UserResponse(long id, String name, String email, List<String> roles,
                               List<String> permissions, Map<String, Object> profile) {}
    public record TokenResponse(String access_token, String token_type, long expires_in, UserResponse user) {}
    private final IdentityRepository identities;
    private final CatalogRepository catalog;
    private final PasswordEncoder passwords;
    private final JwtEncoder encoder;
    private final String issuer;
    private final String audience;
    private final long ttl;
    private final String dummyHash;

    public AuthController(IdentityRepository identities, CatalogRepository catalog, PasswordEncoder passwords,
                          JwtEncoder encoder, @Value("${app.jwt.issuer}") String issuer,
                          @Value("${app.jwt.audience}") String audience,
                          @Value("${app.jwt.ttl-seconds}") long ttl) {
        this.identities = identities; this.catalog = catalog; this.passwords = passwords;
        this.encoder = encoder; this.issuer = issuer; this.audience = audience; this.ttl = ttl;
        this.dummyHash = passwords.encode(java.util.UUID.randomUUID().toString());
    }

    @PostMapping("/login")
    public TokenResponse login(@Valid @RequestBody LoginRequest request) {
        if (request.password().getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Contraseña demasiado larga");
        }
        var account = identities.byDni(request.dni());
        String hash = account.map(IdentityRepository.Account::password).orElse(dummyHash);
        boolean matches = passwords.matches(request.password(), hash);
        if (account.isEmpty() || !matches) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Credenciales incorrectas");
        }
        var user = account.get();
        var now = Instant.now();
        var claims = JwtClaimsSet.builder().issuer(issuer).audience(List.of(audience))
                .subject(Long.toString(user.id())).issuedAt(now).expiresAt(now.plusSeconds(ttl)).build();
        var token = encoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims));
        return new TokenResponse(token.getTokenValue(), "Bearer", ttl, response(user));
    }

    @GetMapping("/me")
    public UserResponse me(Authentication authentication) {
        return response(identities.byId(Long.parseLong(authentication.getName()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED)));
    }

    private UserResponse response(IdentityRepository.Account user) {
        return new UserResponse(user.id(), user.name(), user.email(), identities.roles(user.id()),
                identities.permissions(user.id()), catalog.ownProfile(user.id()).orElse(null));
    }
}
