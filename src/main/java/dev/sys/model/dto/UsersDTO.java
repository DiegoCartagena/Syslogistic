package dev.sys.model.dto;


public class UsersDTO {

	private Integer user_id;
	private String username;
	private String password;
	private int enabled;
	
	private Integer rol_id;
	private String rol;
	
	
	
	public Integer getRol_id() {
		return rol_id;
	}
	public void setRol_id(Integer rol_id) {
		this.rol_id = rol_id;
	}
	public String getRol() {
		return rol;
	}
	public void setRol(String rol) {
		this.rol = rol;
	}
	public Integer getUser_id() {
		return user_id;
	}
	public void setUser_id(Integer user_id) {
		this.user_id = user_id;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public int isEnabled() {
		return enabled;
	}
	public void setEnabled(int enabled) {
		this.enabled = enabled;
	}

	
	public UsersDTO() {
	}
	public UsersDTO(String username, String password, int enabled, String rol) {
		this.username = username;
		this.password = password;
		this.enabled = enabled;
		this.rol = rol;
	
	}
	@Override
	public String toString() {
		return "UsersDTO [user_id=" + user_id + ", username=" + username + ", password=" + password + ", enabled="
				+ enabled + ", rol_id=" + rol_id + ", rol=" + rol + "]";
	}
	
	
}
