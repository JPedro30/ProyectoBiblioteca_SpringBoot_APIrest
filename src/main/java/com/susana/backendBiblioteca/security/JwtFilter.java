package com.susana.backendBiblioteca.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@Component
public class JwtFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // Obtenemos la cabecera Authorization de la petición
        String header = request.getHeader("Authorization");

        // Comprobamos si tiene el formato correcto ("Bearer eyJh...")
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7); // Quitamos la palabra "Bearer "
            
            try {
                // Usamos EXACTAMENTE el mismo secreto que en LoginController
                Algorithm algorithm = Algorithm.HMAC256("secreto_super_seguro_para_la_biblioteca_de_susana");
                JWTVerifier verifier = JWT.require(algorithm)
                        .withIssuer("biblioteca-susana")
                        .build();

                // Si el token es falso o caducó, esto saltará al catch
                DecodedJWT decodedJWT = verifier.verify(token);
                String username = decodedJWT.getSubject();

                // Le decimos a Spring Security que este usuario tiene permiso
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, null, Collections.emptyList());
                SecurityContextHolder.getContext().setAuthentication(auth);

            } catch (Exception e) {
                // Si el token no vale, limpiamos la seguridad por precaución
                SecurityContextHolder.clearContext();
            }
        }

        // Pasamos la petición al siguiente paso
        filterChain.doFilter(request, response);
    }
}
