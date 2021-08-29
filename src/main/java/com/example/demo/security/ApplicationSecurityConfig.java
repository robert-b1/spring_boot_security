package com.example.demo.security;

import com.example.demo.auth.ApplicationUserService;
import com.example.demo.jwt.JwtConfig;
import com.example.demo.jwt.JwtTokenVerifier;
import com.example.demo.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.SecretKey;

import static com.example.demo.security.ApplicationUserRole.STUDENT;

@Configuration
@EnableWebSecurity
/**poniższą adnotację trzeba dodać aby działały adnotacje metod w klasie StudentManagementContoller,
 * odpowiedzialne za przypisywanie dostępu(permission) danym rolą(czyłi adnotacja "@PerAuthorize"
 */
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    //połaczenie z metodą rozszyfrowującą z klasy PasswordConfig + poniżej konstruktor,
    //który to obsługuje
    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;

    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder,
                                     ApplicationUserService applicationUserService,
                                     SecretKey secretKey,
                                     JwtConfig jwtConfig) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                /** csrf.disable(Cross Site Request Forgery - fałszerstwo żądań między lokacjami), zapis ten zapobiega
                 * przed atakiem polegającym na przekierowaniu użytkownika(bez jego wiedzy) i nadaniu atakującemu
                 * dodatkowych uprawnień lub pozwoleniu na uzyskanie drażliwy danych, które może wymusić
                 * na przykład przez link pułapkę
                 */
                //.csrf().disable()
                /**dwie linijki kodu poniżej umożliwiają podejżenie w programie postman wygenerowanego tokena w zakładce
                 * cookie, ale za każdym razem token ten bedzie się zmieniał
                 */
//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                .and()
                .csrf().disable()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                //addFilter dodaje możliwość przefiltrowania zgodności logowania urzytkownika dzięki klasie JwtUsernameAndPasswordAuthenticationFilter
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
                //dodaje kojejny filtr, który jest stwożony w klasie JwtTokenVerifier(dokładny opis w tej klasie)
                .addFilterAfter(new JwtTokenVerifier(secretKey, jwtConfig), JwtUsernameAndPasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                /**dodając zapis poniżej dajemy tylko i wyłacznie ścieżkę dostępu do api(ścieżka rozpoczynająca
                 *się od "/api/coś tam dalej(te gwiastki to znaczą))
                 *Student, który używa loginu i hasła "kajabaja" i "password"
                 */
                .antMatchers("/api/**").hasRole(STUDENT.name())
                /**zakomentowałem poniższy kod ponieważ w klasie StudentManagementContoller do odpowiednich
                 * podopisywałem adnotacje w postaci "@CośtamCośtam" które wykonyją to samo co poniższy kod,
                 * a są bardziej czytelne
                 */
//                /**ale za to dzięki dodaniu kolejnych linijek kodu przyznaj Adminowi dostęp do bazy danych,
//                 *a także umożliwiam usuwale(delete), dodawanie(post) i aktualizowanie(put) bazuy danych
//                 *ale trzeba zmienić ścieżkę dostępu na "/management/api/coś tam (znaczy te gwiazdki)"
//                 */
//                /**po tym jak w metodzie UserDetailsService zakomentowałem .role należy zmienić "COURSE_WRITE.name()"
//                 *na "COURSE_WRITE.getPermission()"
//                 */
//                .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAnyAuthority(COURSE_WRITE.getPermission())
//                /**zapis antMatchers jest rzadko stosowany bo wystarczy dać na początku to:
//                 *".antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())"
//                 *i admintrainee też będzie miał dostęp do usuwania, zapisywania i nadpisywania banych w bazie
//                 *dla tego trzeba pamiętać o odpowiedniej kolejności, można to zapisać adnotacjami czyli @Cośtam przy danych metodach
//                 *i ten drugi sposób jest bardziej czytelny
//                 */
//                .antMatchers(HttpMethod.POST,"/management/api/**").hasAnyAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT,"/management/api/**").hasAnyAuthority(COURSE_WRITE.getPermission())
//                //ta linijka kodu daje dostęp adminowi i admintrainerowi do pobierania danych
//                .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
                .anyRequest()
                .authenticated();
        /**dzięki dodaniu klasy JwtUsernameAndPasswordAuthenticationFilter można całą resztę tej
         * metody zakomentować
         *
         .and()
         .formLogin()
         *ta linijka po wpisaniu w przeglądarkę "localhost/courses" przekierowywuje na stronę logowania
         * a następnie po poprawnym zalogowaniu kolejna linijka przekierowywuje do strony,
         * która jest stworzona w katalogu templates o nazwie "courses.html"
         *
         .loginPage("/login")
         .permitAll()
         .defaultSuccessUrl("/courses", true)
         .passwordParameter("password")
         .usernameParameter("username")
         /**te dwie linijki kodu pozwalają na zapamiętanie zalogowanego użytkownika na okres 21 dni
         * na stronie po zalogowaniu
         *
         .and()
         .rememberMe()
         .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
         .key("cośdobrzezabezpieczonego")
         .rememberMeParameter("remember-me")
         //kolejne linijki służą do wylogowywania się i do następujących rzeczy:
         .and()
         .logout()
         .logoutUrl("/logout")//wylogowanie URL
         .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
         .clearAuthentication(true)//czyszczenie legalizacji(nadanej ważności)
         .invalidateHttpSession(true)//unieważnienie sesji
         .deleteCookies("JSESSIONID", "remember-me")//usuwanie wymienionych ciasteczek
         .logoutSuccessUrl("/login");//po udanym wylogowaniu przekieruje do strony logowania
         */
    }


    /**
     * aby klasa ApplicationUserServise w pakiecie auth poprawnie działała należy nadpisać poniższą
     * metodę oraz dodać metodę Bean'a DaoAuthenticationProvider
     *
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }


    /**ta metoda została zakomentowana ponieważ została stworzona klasa "ApplicationUserServise"
     * w pakiecie "auth", a w niej została utworzona taka sama metoda, ale bardziej zwięzła

     //metoda umożliwiająca dopisanie do każdego użytkownika unikalnej nazwy i hasła
     //twożymy w paczce security klase PasswordConfig
     @Override
     @Bean protected UserDetailsService userDetailsService() {
     //User.UserBuilder kajaBajaUser = User.builder()
     //żeby nie pisać buildera tak jak wyżej można zapisać to przy pomocy UserDetails,
     //ale na końcu trzeba dopisać .build
     UserDetails kajaBajaUser = User.builder()
     .username("kajabaja")
     //żeby poprawnie działało rozszyfrowywanie trzeba dodać w nawiasie "passwordEncoder.encode
     //i w kolejnym nawiasie dane hasło
     .password(passwordEncoder.encode("password"))
     //po dodaniu i przyznaniu danym userom oczekiwanych permission możemy zmienieć ten zapis:
     //.roles("STUDENT")// ROLE_STUDENT
     //na ten
     //.roles(ApplicationUserRole.STUDENT.name())// ROLE_STUDENT
     //i klikając w STUDENT importujemy i skracamy to do takiej formy
     //                .roles(STUDENT.name())// ROLE_STUDENT
     //po zakomentowaniu .roles(STUDENT.name())// ROLE_STUDENT i napisaniu metod getPermissions()i
     //getGrantedAuthorities możemy urzyć tego zapisu
     .authorities(STUDENT.getGrantedAuthorities())
     .build();

     //dodaje kolejnego urzytkownika, który w bedzie administratorem
     UserDetails robertAdmin = User.builder()
     .username("robert")
     .password(passwordEncoder.encode("password1234"))
     //po dodaniu i przyznaniu danym userom oczekiwanych permission możemy zmienieć ten zapis:
     //..roles("ADMIN")
     //na ten
     //.roles(ApplicationUserRole.ADMIN.name())// ROLE_ADMIN
     //i klikając w STUDENT importujemy i skracamy to do takiej formy
     //                .roles(ADMIN.name())
     .authorities(ADMIN.getGrantedAuthorities())
     .build();

     //dodaje kolejnego urzytkownika
     UserDetails michaltAdmin = User.builder()
     .username("michal")
     .password(passwordEncoder.encode("password1234"))
     //                .roles(ADMINTRAINEE.name())//ROLE_ADMINTRAINEE
     .authorities(ADMINTRAINEE.getGrantedAuthorities())
     .build();

     return new InMemoryUserDetailsManager(
     kajaBajaUser,
     robertAdmin,
     michaltAdmin
     );
     }

     */
}
