package com.bibliotecareservas.apireservasuch.identity;

import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class IdentityRepository {
    public record Account(long id, String name, String email, String password) {}
    private final JdbcClient jdbc;
    private final String guard;
    private final String modelType;

    public IdentityRepository(JdbcClient jdbc, @Value("${app.laravel.guard}") String guard,
                              @Value("${app.laravel.model-type}") String modelType) {
        this.jdbc = jdbc;
        this.guard = guard;
        this.modelType = modelType;
    }

    public Optional<Account> byDni(String dni) {
        return jdbc.sql("""
                SELECT u.id, u.name, u.email, u.password FROM users u
                JOIN profiles p ON p.user_id = u.id
                WHERE p.dni = :dni
                """).param("dni", dni).query(Account.class).optional();
    }

    public Optional<Account> byId(long id) {
        return jdbc.sql("SELECT id, name, email, password FROM users WHERE id = :id")
                .param("id", id).query(Account.class).optional();
    }

    public List<String> roles(long id) {
        return jdbc.sql("""
                SELECT DISTINCT r.name FROM roles r
                JOIN model_has_roles mr ON mr.role_id = r.id
                WHERE mr.model_id = :id AND mr.model_type = :type AND r.guard_name = :guard
                ORDER BY r.name
                """).param("id", id).param("type", modelType).param("guard", guard)
                .query(String.class).list();
    }

    public List<String> permissions(long id) {
        return jdbc.sql("""
                SELECT DISTINCT p.name FROM permissions p
                WHERE p.guard_name = :guard AND (
                    EXISTS (SELECT 1 FROM model_has_permissions mp
                            WHERE mp.permission_id = p.id AND mp.model_id = :id AND mp.model_type = :type)
                    OR EXISTS (SELECT 1 FROM role_has_permissions rp
                               JOIN roles r ON r.id = rp.role_id
                               JOIN model_has_roles mr ON mr.role_id = r.id
                               WHERE rp.permission_id = p.id AND r.guard_name = :guard
                                 AND mr.model_id = :id AND mr.model_type = :type)
                ) ORDER BY p.name
                """).param("id", id).param("type", modelType).param("guard", guard)
                .query(String.class).list();
    }
}
