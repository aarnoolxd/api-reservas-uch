package com.bibliotecareservas.apireservasuch.catalog;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class CatalogRepository {
    private static final String PROFILE_FIELDS = "id, user_id, dni, first_name, last_name, maternal_last_name, program, cycle, user_type, phone, address, photo, created_at, updated_at";
    private static final String EQUIPMENT_FIELDS = "id, patrimonial_code, type, brand, model, serial_number, status, observations, created_at, updated_at";
    public record Page(List<Map<String, Object>> data, long total, int page, int per_page) {}
    private final JdbcClient jdbc;

    public CatalogRepository(JdbcClient jdbc) { this.jdbc = jdbc; }

    public Optional<Map<String, Object>> ownProfile(long userId) {
        return jdbc.sql("SELECT " + PROFILE_FIELDS + " FROM profiles WHERE user_id = :id")
                .param("id", userId).query().listOfRows().stream().findFirst();
    }

    public Page profiles(int page, int size) {
        return page("profiles", PROFILE_FIELDS, page, size);
    }

    public Page equipment(int page, int size) {
        return page("equipment", EQUIPMENT_FIELDS, page, size);
    }

    public Optional<Map<String, Object>> profile(long id) { return one("profiles", PROFILE_FIELDS, id); }
    public Optional<Map<String, Object>> equipment(long id) { return one("equipment", EQUIPMENT_FIELDS, id); }

    // Table and column identifiers come only from constants above, never from request parameters.
    private Page page(String table, String fields, int page, int size) {
        var rows = jdbc.sql("SELECT " + fields + " FROM " + table + " ORDER BY id LIMIT :limit OFFSET :offset")
                .param("limit", size).param("offset", ((long) page - 1) * size).query().listOfRows();
        long total = jdbc.sql("SELECT COUNT(*) FROM " + table).query(Long.class).single();
        return new Page(rows, total, page, size);
    }

    private Optional<Map<String, Object>> one(String table, String fields, long id) {
        return jdbc.sql("SELECT " + fields + " FROM " + table + " WHERE id = :id")
                .param("id", id).query().listOfRows().stream().findFirst();
    }
}
