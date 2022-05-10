package com.example.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static com.example.demo.security.ApplicationUserPermissions.COURSE_WRITE;
import static com.example.demo.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception{
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())     // erlaubt der Rolle Student alle url mit /api/... zu besuchens
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                    .loginPage("/login")// um ein custom login page weiterzuleiten
                    .permitAll()
                    .defaultSuccessUrl("/courses",true)     // defaultSuccessUrl leitet den Nutzer bei erfolgreichen Login zu der angegeben route weiter.
                    .usernameParameter("username")  // falls das input aus der Login form einen anderen wert in dem name property hat kann man das hier spezifizieren
                    .passwordParameter("password")

                .and()
                // .and().rememberMe() aktiviert remember me option falls eine checkbox in der Login page form definiert ist. Remembers for 2 weeks.
                .rememberMe().
                    tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))  // durch .tokenValiditySeconds kann man eine eigene Expiration Zeit angeben
                    .key("somethingverysecured")
                    .rememberMeParameter("remember-me") // falls das input aus der Login form einen anderen wert in dem name property hat kann man das hier spezifizieren
                .and()
                .logout()
                    .logoutUrl("/logout")
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID", "remember-me")
                    .logoutSuccessUrl("/login");
    }

    // Grant defined User access with their username & password
    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails annaSmithUser = User.builder()
                .username("annasmith")
                .password(passwordEncoder.encode("password"))
                //.roles(STUDENT.name())       // ROLE_STUDENT What spring makes under the hood.
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        // Second User Linda with the role ADMIN
        UserDetails lindaUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password123"))
                //.roles(ADMIN.name())
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        // third User Tom with the role ADMIN
        UserDetails tomUser = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("password123"))
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                //.roles(ADMINTRAINEE.name())
                .build();

        return new InMemoryUserDetailsManager(annaSmithUser, lindaUser, tomUser);
    }
}
