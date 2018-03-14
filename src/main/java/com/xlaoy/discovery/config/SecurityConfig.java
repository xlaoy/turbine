package com.xlaoy.discovery.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;


@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private static final String SYSTEM_API_USER_NAME = "turbine";
    private static final String SYSTEM_API_USER_PASSWORD = "123456";
    private static final String SYSTEM_API_ACCESS_ROLE = "TURBINE_API";

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
            .passwordEncoder(new SimplePasswordEncoder())
            .withUser(SYSTEM_API_USER_NAME)
            .password(SYSTEM_API_USER_PASSWORD)
            .roles(SYSTEM_API_ACCESS_ROLE);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .httpBasic().and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
            .authorizeRequests()
            .anyRequest().hasRole(SYSTEM_API_ACCESS_ROLE);
    }

    private class SimplePasswordEncoder implements PasswordEncoder {

        @Override
        public String encode(CharSequence charSequence) {
            return charSequence.toString();
        }

        @Override
        public boolean matches(CharSequence charSequence, String s) {
            return charSequence.equals(s);
        }
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers(
            "/application/**",
            "/error",
            "/favicon.ico"
        );
    }
}
