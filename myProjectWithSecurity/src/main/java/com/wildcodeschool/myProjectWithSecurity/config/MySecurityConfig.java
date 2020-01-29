package com.wildcodeschool.myProjectWithSecurity.config;

import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.beans.factory.support.MethodOverride;
import java.util.*;
import static org.springframework.security.config.Customizer.withDefaults;
import org.springframework.web.bind.annotation.*;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.expression.SecurityExpressionRoot.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;


@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter{

@Override
protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
auth.inMemoryAuthentication()
     .withUser("Steve Guy")
     	.password(encoder.encode("12345678"))
	.roles("AVENGER")
	.and()
     .withUser("Tony Stark")
        .password(encoder.encode("87654321"))
        .roles("AVENGER")
	.and()
     .withUser("Nick Fury")
        .password(encoder.encode("Hello123"))
        .roles("DIRECTOR");


}

//public static class UserLogin extends WebSecurityConfigurerAdapter {
@Override
protected void configure(HttpSecurity http) throws Exception {
        http
		.authorizeRequests()
                .antMatchers("/avengers/assemble").hasRole("AVENGER")
                .antMatchers("/secret-bases").hasRole("DIRECTOR")
		.antMatchers("/").permitAll()
		.anyRequest().authenticated()
              // .and()
            // .formLogin()
                .and()
                .httpBasic();

}
}
