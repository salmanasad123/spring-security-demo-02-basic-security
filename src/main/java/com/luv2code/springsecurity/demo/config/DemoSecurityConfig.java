package com.luv2code.springsecurity.demo.config;


import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;

@Configuration
@EnableWebSecurity
public class DemoSecurityConfig extends WebSecurityConfigurerAdapter {

    // override this method to setup in memory authentication using authentication manager builder
    // we setup in memory authentication manager
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // add our users for in memory authentication

        User.UserBuilder users = User.withDefaultPasswordEncoder();

        // creating in memory users, we'll replace with database
        auth.inMemoryAuthentication()
                .withUser(users.username("john").password("test123").roles("EMPLOYEE"));
        auth.inMemoryAuthentication()
                .withUser(users.username("mary").password("test123").roles("MANAGER"));
        auth.inMemoryAuthentication()
                .withUser(users.username("susan").password("test123").roles("ADMIN"));
    }

    
}
