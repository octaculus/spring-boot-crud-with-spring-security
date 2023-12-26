package com.emp.main.configuration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
@Configuration
public class SecurityConfiguration{

    @Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.csrf().disable()
			.authorizeHttpRequests((authorize) -> authorize
				.requestMatchers("/**").permitAll()
				.anyRequest().authenticated()
			);

		return http.build();
	}

    // @Bean
	// UserDetailsManager inMemoryUserDetailsManager() {
	// 	var user1 = User.withUsername("user").password("{noop}password").roles("USER").build();
	// 	var user2 = User.withUsername("admin").password("{noop}password").roles("USER", "ADMIN").build();
	// 	return new InMemoryUserDetailsManager(user1, user2);
	// }
/* 
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
		.authorizeHttpRequests((authorize) -> authorize
			.requestMatchers("/css/**", "/favicon.ico", "/", "/index").permitAll()
			// .requestMatchers("/user").hasAnyRole("USER")
			// .requestMatchers("/admin").hasAnyRole("ADMIN")
			.anyRequest().authenticated()
		)
		// .formLogin(login -> login
		// 		.defaultSuccessUrl("/")
		// 		.permitAll())
		// .logout(logout -> logout
		// 		.logoutSuccessUrl("/"));
        .formLogin(withDefaults());
        return http.build();
    }*/

    // @Bean
	// PasswordEncoder passwordEncoder() {
	// 	return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	// }
    
}
