package com.bibliotecareservas.apireservasuch.catalog;

import java.util.Map;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1")
public class CatalogController {
    private final CatalogRepository catalog;
    public CatalogController(CatalogRepository catalog) { this.catalog = catalog; }

    @GetMapping("/profiles/me")
    public Map<String, Object> ownProfile(Authentication authentication) {
        return catalog.ownProfile(Long.parseLong(authentication.getName()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    @GetMapping("/profiles")
    @PreAuthorize("hasAuthority('ViewAny_Profile')")
    public CatalogRepository.Page profiles(@RequestParam(defaultValue="1") @Min(1) int page,
                                            @RequestParam(defaultValue="20") @Min(1) @Max(100) int per_page) {
        return catalog.profiles(page, per_page);
    }

    @GetMapping("/profiles/{id}")
    @PreAuthorize("hasAuthority('View_Profile')")
    public Map<String, Object> profile(@PathVariable @Min(1) long id) {
        return catalog.profile(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    @GetMapping("/equipment")
    @PreAuthorize("hasAuthority('ViewAny_Equipment')")
    public CatalogRepository.Page equipment(@RequestParam(defaultValue="1") @Min(1) int page,
                                             @RequestParam(defaultValue="20") @Min(1) @Max(100) int per_page) {
        return catalog.equipment(page, per_page);
    }

    @GetMapping("/equipment/{id}")
    @PreAuthorize("hasAuthority('View_Equipment')")
    public Map<String, Object> equipment(@PathVariable @Min(1) long id) {
        return catalog.equipment(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }
}
