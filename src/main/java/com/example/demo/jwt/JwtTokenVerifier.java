package com.example.demo.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Klasa ta jest(tworzy) kolejny filtr do sprawdzenia czy token utworzony przez serwer po zalogowaniu urzytkownika
 * jest poprawny, czyli sprawdza czy token nie został podrobiony przez potencjalnego "włamywacza".
 * Filtr ten zostanie uruchomiony po klasie(filtrze) JwtUsernameAndPasswordAuthenticationFilter
 */
public class JwtTokenVerifier extends OncePerRequestFilter {

    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;

    public JwtTokenVerifier(SecretKey secretKey,
                            JwtConfig jwtConfig) {
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }

    //nadpisuje metodę dziedziczoną po klasie OncePerRequestFilter, która pobiera cały token i go bada
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        //zmienna, która jest całym tokenem wraz z nagłówkiem
        String authorizationHeader = request.getHeader(jwtConfig.getAuthorizationHeader());

        //sprawdzenie(porównanie), czy zmienna authorizationHeader nie jest pusta i czy zaczyna się odpowiednim nagłówkiem
        if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(jwtConfig.getTokenPrefix())) {
            filterChain.doFilter(request, response);
            return;
        }

        //utwożenie zmiennej, która będzie zawierać sam czysty token nadany przez serwer bez nagłówka "Bearer"
        String token = authorizationHeader.replace(jwtConfig.getTokenPrefix(), "");

        //próba przechwycenia potencjalnego błędu lub niezgodności tokena
        try {
            //czysty token utworzony przez serwer

            //porównuje czy sekretny token otrzymany z serwera jest identyczy z tokenem, którym posługuje sie urzytkownik
            Jws<Claims> claimsJws = Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(token);

            //przypisanie body tokena
            Claims body = claimsJws.getBody();
            //wyodrębnienie z body tylko nazwy urzytkownika
            String username = body.getSubject();

            //tworzę zmienną, która zawiera listę mapującą wszystkie authorities(władze) danego urzytkownika
            var authorities = (List<Map<String, String>>) body.get("authorities");

            //mapowanie
            Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorities.stream()
                    .map(m -> new SimpleGrantedAuthority(m.get("authority")))
                    .collect(Collectors.toSet());

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    simpleGrantedAuthorities
            );
            //jeśli cały proces porównywania zgodności tokena przebiegnie prawidłowo otrzymuje potwierdzenie autoryzacji
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        //jeśli jednak coś się nie zgadza to wyrzuci bład
        catch (JwtException e) {
            throw new IllegalStateException(String.format("Token %s cannot be truest", token));
        }

        //ta linijka kodu daje pewność, że klasa ta będzie (a dokładnie porównanie otrzymanego tokena z
        // właśnie urzywanym) należeć do łańcucha filtrów tej aplikacji
        filterChain.doFilter(request, response);
    }
}
