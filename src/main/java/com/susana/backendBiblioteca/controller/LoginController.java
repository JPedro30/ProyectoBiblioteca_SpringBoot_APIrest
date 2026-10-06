package com.susana.backendBiblioteca.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/login")
public class LoginController {

    // Record para mapear el JSON que envía React automáticamente
    public record LoginRequest(String usuario, String password) {}

    @PostMapping
    public ResponseEntity<?> autenticar(@RequestBody LoginRequest peticion) {
        
        // 1. Validamos las credenciales (ponemos las que tienes en el frontend temporalmente)
        // Nota: Si en el futuro quieres cambiar la contraseña, la cambias aquí.
        if ("admin".equals(peticion.usuario()) && "lilo".equals(peticion.password())) {
            
            // 2. Creamos la firma del token (el secreto debe ser difícil de adivinar)
            Algorithm algorithm = Algorithm.HMAC256("secreto_super_seguro_para_la_biblioteca_de_susana");
            
            // 3. Generamos el token con la librería Auth0
            String tokenGenerado = JWT.create()
                    .withIssuer("biblioteca-susana")
                    .withSubject(peticion.usuario())
                    // Le damos 24 horas de validez (86.400.000 milisegundos)
                    .withExpiresAt(new Date(System.currentTimeMillis() + 86400000)) 
                    .sign(algorithm);

            // 4. Lo preparamos como un JSON: { "token": "eyJh..." }
            Map<String, String> respuesta = new HashMap<>();
            respuesta.put("token", tokenGenerado);
            
            return ResponseEntity.ok(respuesta);
        }

        // Si las credenciales fallan, devolvemos un 401 Unauthorized
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Credenciales incorrectas");
    }
}
