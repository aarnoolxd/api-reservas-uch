package com.bibliotecareservas.apireservasuch.web;

import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.server.ResponseStatusException;

@RestControllerAdvice
public class ApiExceptionHandler {
    // Never echo rejected credentials or exception details into responses or validation logs.
    @ExceptionHandler({MethodArgumentNotValidException.class, HandlerMethodValidationException.class,
            HttpMessageNotReadableException.class})
    ResponseEntity<Map<String, String>> invalidInput(Exception exception) {
        return ResponseEntity.badRequest().body(Map.of("message", "Datos de solicitud inválidos"));
    }

    @ExceptionHandler(ResponseStatusException.class)
    ResponseEntity<Map<String, String>> status(ResponseStatusException exception) {
        String message = switch (exception.getStatusCode().value()) {
            case 401 -> "Credenciales incorrectas";
            case 404 -> "Recurso no encontrado";
            default -> "Solicitud no válida";
        };
        return ResponseEntity.status(exception.getStatusCode()).body(Map.of("message", message));
    }
}
