package dev.sys.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


@Configuration
@EnableWebSecurity
public class SecurityJdbc extends WebSecurityConfigurerAdapter {

	@Autowired
	private DataSource dataSource;

	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
		.antMatchers("/User/delete","/BL/delete","/BL/list" ,"/BL/get","/User/get", "/User").hasAuthority("ROLE_Admin")
		.antMatchers("/BL/insert","/User/insert","/User/list","/User/get","/User/update", "/BL/update").hasAnyAuthority("ROLE_Editor", "ROLE_Admin")
		.antMatchers("/BL/list","/BL/get","/index").hasAnyAuthority("ROLE_Admin","ROLE_Editor","ROLE_User")
		.antMatchers( "/images/*").permitAll()
		.antMatchers("/","/js/BL.js","/Aprobado","/js/User.js","/home").permitAll()
		;
		
		http
		.authorizeRequests()
		.anyRequest().authenticated()
		.and()
		.formLogin()
			.loginPage("/login").permitAll() //todos pueden ingresar a la página login
			.and()
			.logout()
				.permitAll() //todos pueden des loggearse
	
		; 
	
		http.exceptionHandling().accessDeniedPage("/403")
		;
	
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth
			.jdbcAuthentication()
			.dataSource(dataSource)
			.passwordEncoder(passwordEncoder())
			.usersByUsernameQuery("SELECT username,password,enabled FROM users WHERE username=?")
			.authoritiesByUsernameQuery(
					"SELECT u.username, r.rol " +
					"FROM users_rol ur, users u , rol r " +
					"WHERE u.user_id = ur.user_id and r.rol_id = ur.rol_id and u.username=?"
			);	
		
	}
		
		
	
	 @Bean
	    public PasswordEncoder passwordEncoder() {
	        return new BCryptPasswordEncoder();
	    }


	 
	
		
}
