package com.example.demo.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;

/**
 * klasa utworzona po dodaniu do pom.xml dependency Java Json Web Token(jjwt), która
 * służy do "przefiltrowywania" nazw urzttkowników i haseł do nich podłączonych, dzięki
 * dziedziczeniu po klasie UsernamePasswordAuthenticationFilter
 * jjwt - podczas połączenia urzytkownika z serwerem, urzytkownik loguje się, serwer gdy go rozpozna
 * wysyła w odpowiedzi token składający się z trzech części (nagłówka(header), ładunku(payload) i
 * zweryfikowanego podpisu(verify signature), token ten jest wtedy urzywany do identyfikacji urzytkownika
 * przez serwer
 */
public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;

    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager,
                                                      JwtConfig jwtConfig,
                                                      SecretKey secretKey) {
        this.authenticationManager = authenticationManager;
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }

    //ta metoda sprawadza/porównóje zgodność nazwy urzytkownika i hasła
    // (authentication - poświadczenie, legalizacja,nadanie ważności)
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {
        //tu próbuje wyłapać nazwę urzytkownika
        try {

            UsernameAndPasswordAuthenticationRequest authenticationRequest = new ObjectMapper()
                    .readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class);
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(),//ten obiekt ma harakter principal-taki szef, dyrektor, najważniejsza część
                    authenticationRequest.getPassword()//ten obiekt jest credentials - potwierdzenie, uwierzytelnienie
            );
            //authenticationManager sprawdza czy urzytkownik z takim username istnieje i
            // czy dane hasło jest z nim powiązane i pasuje
            Authentication authenticate = authenticationManager.authenticate(authentication);
            return authenticate;
            // jeśli coś jest nie tak to wyrzuci RuntimeException
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * jeśli metoda attemptAuthentication(ta wyżej) wykona się poprawnie (czyli
     * urzytkownik podał prawidłową nazwę i hasło) to metoda successfulAuthentication
     * zostanie uruchomiona i utworzy token, który zostanie wysłany do zalogowanego
     * przed chwilą urzytkownika
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain, Authentication authResult) throws IOException, ServletException {

        /**dzięki Jwts.builder() buduję token składający się z
         * trzech części(header, payload i verify signature)
         */
        String token = Jwts.builder()
                //header - w tym przypadku nazwa urzytkownika
                .setSubject(authResult.getName())
                //payload czyli body składający się z:
                .claim("authorities", authResult.getAuthorities())
                .setIssuedAt(new Date())
                //w tym wypadku token bedzie aktywny dwa tygodnie
                .setExpiration(java.sql.Date.valueOf(LocalDate.now().plusDays(jwtConfig.getTokenExpirationAfterDays())))
                //verify signature - zalecane jest żeby zabezbieczenie miało odpowiednią długość(im dłuższe tym lepiej)
                .signWith(secretKey)
                .compact();

        response.addHeader(jwtConfig.getAuthorizationHeader(), jwtConfig.getTokenPrefix() + token);
    }
}
