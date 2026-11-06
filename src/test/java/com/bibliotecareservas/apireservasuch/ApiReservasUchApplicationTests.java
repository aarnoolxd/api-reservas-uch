package com.bibliotecareservas.apireservasuch;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {
    "spring.config.import=",
    "spring.datasource.url=jdbc:h2:mem:reservas;MODE=MySQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1",
    "spring.datasource.username=sa", "spring.datasource.password=",
    "app.jwt.secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "spring.sql.init.mode=never"
})
@AutoConfigureMockMvc
class ApiReservasUchApplicationTests {
    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired PasswordEncoder passwords;
    @Autowired JwtEncoder encoder;
    @Autowired ObjectMapper json;
    private static final String MODEL = "App\\Models\\User";

    @BeforeEach
    void fixtures() {
        jdbc.execute("DROP ALL OBJECTS");
        jdbc.execute("CREATE TABLE users(id BIGINT PRIMARY KEY, name VARCHAR(255), email VARCHAR(255), password VARCHAR(255))");
        jdbc.execute("CREATE TABLE roles(id BIGINT PRIMARY KEY, name VARCHAR(255), guard_name VARCHAR(255))");
        jdbc.execute("CREATE TABLE permissions(id BIGINT PRIMARY KEY, name VARCHAR(255), guard_name VARCHAR(255))");
        jdbc.execute("CREATE TABLE model_has_roles(role_id BIGINT, model_id BIGINT, model_type VARCHAR(255))");
        jdbc.execute("CREATE TABLE model_has_permissions(permission_id BIGINT, model_id BIGINT, model_type VARCHAR(255))");
        jdbc.execute("CREATE TABLE role_has_permissions(role_id BIGINT, permission_id BIGINT)");
        jdbc.execute("CREATE TABLE profiles(id BIGINT PRIMARY KEY, user_id BIGINT UNIQUE, dni VARCHAR(8), first_name VARCHAR(255), last_name VARCHAR(255), maternal_last_name VARCHAR(255), program VARCHAR(255), cycle INT, user_type VARCHAR(255), phone VARCHAR(20), address VARCHAR(255), photo VARCHAR(255), created_at TIMESTAMP, updated_at TIMESTAMP)");
        jdbc.execute("CREATE TABLE equipment(id BIGINT PRIMARY KEY, patrimonial_code VARCHAR(255), type VARCHAR(255), brand VARCHAR(255), model VARCHAR(255), serial_number VARCHAR(255), status VARCHAR(255), observations TEXT, created_at TIMESTAMP, updated_at TIMESTAMP)");
        jdbc.update("INSERT INTO users VALUES(1, 'Test', 'test@example.com', ?)", passwords.encode("correct-password").replace("$2a$", "$2y$"));
        jdbc.update("INSERT INTO users VALUES(2, 'Other', 'other@example.com', ?)", passwords.encode("other-password"));
        jdbc.update("INSERT INTO profiles(id,user_id,dni,first_name) VALUES(1,1,'12345678','Test'),(2,2,'87654321','Other'),(3,NULL,'11111111','Unlinked')");
        jdbc.update("INSERT INTO equipment(id,patrimonial_code,type,status) VALUES(1,'PC-01','Computadora','Disponible')");
        jdbc.update("INSERT INTO roles VALUES(1,'alumno','web'),(2,'external','api')");
        jdbc.update("INSERT INTO permissions VALUES(1,'ViewAny_Equipment','web'),(2,'View_Equipment','web'),(3,'ViewAny_Profile','web'),(4,'View_Profile','web'),(5,'View_Profile','api')");
        jdbc.update("INSERT INTO model_has_roles VALUES(1,1,?)", MODEL);
        jdbc.update("INSERT INTO role_has_permissions VALUES(1,1)");
        jdbc.update("INSERT INTO model_has_permissions VALUES(2,1,?)", MODEL);
    }

    private String login() throws Exception {
        var response = mvc.perform(post("/api/v1/auth/login").contentType("application/json")
                .content("{\"dni\":\"12345678\",\"password\":\"correct-password\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.user.password").doesNotExist())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.user.roles[0]").value("alumno"))
                .andReturn().getResponse().getContentAsString();
        return json.readTree(response).get("access_token").asText();
    }

    @Test void laravelBcryptLoginAndCurrentUser() throws Exception {
        String token = login();
        mvc.perform(get("/api/v1/auth/me").header("Authorization","Bearer " + token))
                .andExpect(status().isOk()).andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.profile.dni").value("12345678"))
                .andExpect(jsonPath("$.password").doesNotExist());
    }

    @Test void invalidCredentialsAndValidation() throws Exception {
        for (String dni : List.of("12345678", "99999999", "11111111")) {
            mvc.perform(post("/api/v1/auth/login").contentType("application/json")
                    .content("{\"dni\":\"" + dni + "\",\"password\":\"wrong\"}"))
                    .andExpect(status().isUnauthorized());
        }
        mvc.perform(post("/api/v1/auth/login").contentType("application/json").content("{}"))
                .andExpect(status().isBadRequest());
    }

    @Test void dniMustContainExactlyEightDigitsAndEmailIsNotAccepted() throws Exception {
        for (String dni : List.of("", "1234567", "123456789", "1234567A", " 12345678", "１２３４５６７８")) {
            mvc.perform(post("/api/v1/auth/login").contentType("application/json")
                    .content(json.writeValueAsString(java.util.Map.of("dni", dni, "password", "correct-password"))))
                    .andExpect(status().isBadRequest());
        }
        mvc.perform(post("/api/v1/auth/login").contentType("application/json")
                .content(json.writeValueAsString(java.util.Map.of("email", "test@example.com", "password", "correct-password"))))
                .andExpect(status().isBadRequest());
    }

    @Test void leadingZerosArePreservedInDni() throws Exception {
        jdbc.update("UPDATE profiles SET dni='01234567' WHERE user_id=1");
        mvc.perform(post("/api/v1/auth/login").contentType("application/json")
                .content(json.writeValueAsString(java.util.Map.of("dni", "01234567", "password", "correct-password"))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.user.id").value(1));
    }

    @Test void dniMustHaveLinkedAccountWithItsOwnPassword() throws Exception {
        for (String dni : List.of("11111111", "99999999", "87654321")) {
            mvc.perform(post("/api/v1/auth/login").contentType("application/json")
                    .content(json.writeValueAsString(java.util.Map.of("dni", dni, "password", "correct-password"))))
                    .andExpect(status().isUnauthorized());
        }
        mvc.perform(post("/api/v1/auth/login").contentType("application/json")
                .content(json.writeValueAsString(java.util.Map.of("dni", "87654321", "password", "other-password"))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.user.id").value(2));
        jdbc.update("DELETE FROM profiles WHERE user_id=1");
        mvc.perform(post("/api/v1/auth/login").contentType("application/json")
                .content(json.writeValueAsString(java.util.Map.of("dni", "12345678", "password", "correct-password"))))
                .andExpect(status().isUnauthorized());
    }

    @Test void longUnicodePasswordReturnsBadRequestWithoutEchoingIt() throws Exception {
        mvc.perform(post("/api/v1/auth/login").contentType("application/json")
                .content(json.writeValueAsString(java.util.Map.of("dni", "12345678", "password", "é".repeat(40)))))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.password").doesNotExist());
    }

    @Test void anonymousAndMalformedTokensAreRejected() throws Exception {
        mvc.perform(get("/api/v1/equipment")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/equipment").header("Authorization","Bearer invalid"))
                .andExpect(status().isUnauthorized());
    }

    @Test void roleAndDirectPermissionsAndPagination() throws Exception {
        String token = login();
        mvc.perform(get("/api/v1/equipment").header("Authorization","Bearer " + token))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data[0].patrimonial_code").value("PC-01"))
                .andExpect(jsonPath("$.total").value(1));
        mvc.perform(get("/api/v1/equipment/1").header("Authorization","Bearer " + token)).andExpect(status().isOk());
        mvc.perform(get("/api/v1/equipment/999").header("Authorization","Bearer " + token)).andExpect(status().isNotFound());
        mvc.perform(get("/api/v1/equipment?page=0").header("Authorization","Bearer " + token)).andExpect(status().isBadRequest());
        mvc.perform(get("/api/v1/equipment?per_page=101").header("Authorization","Bearer " + token)).andExpect(status().isBadRequest());
    }

    @Test void permissionRevocationAppliesToExistingToken() throws Exception {
        String token = login();
        jdbc.update("DELETE FROM role_has_permissions");
        mvc.perform(get("/api/v1/equipment").header("Authorization","Bearer " + token)).andExpect(status().isForbidden());
        mvc.perform(get("/api/v1/equipment/1").header("Authorization","Bearer " + token)).andExpect(status().isOk());
        jdbc.update("DELETE FROM model_has_permissions");
        mvc.perform(get("/api/v1/equipment/1").header("Authorization","Bearer " + token)).andExpect(status().isForbidden());
    }

    @Test void ownProfileDoesNotGrantAccessToOtherProfiles() throws Exception {
        String token = login();
        mvc.perform(get("/api/v1/profiles/me").header("Authorization","Bearer " + token))
                .andExpect(status().isOk()).andExpect(jsonPath("$.id").value(1));
        mvc.perform(get("/api/v1/profiles/2").header("Authorization","Bearer " + token)).andExpect(status().isForbidden());
        mvc.perform(get("/api/v1/profiles").header("Authorization","Bearer " + token)).andExpect(status().isForbidden());
        jdbc.update("INSERT INTO model_has_permissions VALUES(3,1,?),(4,1,?)",MODEL,MODEL);
        mvc.perform(get("/api/v1/profiles").header("Authorization","Bearer " + token))
                .andExpect(status().isOk()).andExpect(jsonPath("$.total").value(3));
        mvc.perform(get("/api/v1/profiles/2").header("Authorization","Bearer " + token)).andExpect(status().isOk());
    }

    @Test void otherGuardsAndModelTypesDoNotGrantPermissions() throws Exception {
        String token = login();
        jdbc.update("INSERT INTO model_has_permissions VALUES(4,1,'OtherModel')");
        jdbc.update("INSERT INTO model_has_permissions VALUES(5,1,?)",MODEL);
        mvc.perform(get("/api/v1/profiles/2").header("Authorization","Bearer " + token)).andExpect(status().isForbidden());
    }

    @Test void deletedAccountCannotUseExistingToken() throws Exception {
        String token = login();
        jdbc.update("DELETE FROM users WHERE id=1");
        mvc.perform(get("/api/v1/auth/me").header("Authorization","Bearer " + token)).andExpect(status().isUnauthorized());
    }

    @Test void expiredAndWrongAudienceAndWrongIssuerRejected() throws Exception {
        for (int scenario = 0; scenario < 3; scenario++) {
            var now = Instant.now();
            var claims = JwtClaimsSet.builder().subject("1").issuedAt(now.minusSeconds(300))
                    .issuer(scenario == 2 ? "other" : "api-reservas-uch")
                    .audience(List.of(scenario == 1 ? "other" : "reservas-react"))
                    .expiresAt(scenario == 0 ? now.minusSeconds(120) : now.plusSeconds(900)).build();
            String token = encoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(),claims)).getTokenValue();
            mvc.perform(get("/api/v1/auth/me").header("Authorization","Bearer " + token)).andExpect(status().isUnauthorized());
        }
    }

    @Test void missingProfileIsHandledAndCorsAllowsReact() throws Exception {
        String token = login();
        jdbc.update("DELETE FROM profiles WHERE user_id=1");
        mvc.perform(get("/api/v1/auth/me").header("Authorization","Bearer " + token)).andExpect(status().isOk());
        mvc.perform(get("/api/v1/profiles/me").header("Authorization","Bearer " + token)).andExpect(status().isNotFound());
        mvc.perform(options("/api/v1/auth/login").header("Origin","http://localhost:5173")
                .header("Access-Control-Request-Method","POST").header("Access-Control-Request-Headers","content-type"))
                .andExpect(status().isOk()).andExpect(header().string("Access-Control-Allow-Origin","http://localhost:5173"));
    }
}
