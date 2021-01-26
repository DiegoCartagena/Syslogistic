package dev.sys.model.dto;

public class AA_ClienteDTO {
	private Integer id_cliente;
	private String nombre_cl;
	private String direccion;
	private Integer telefono;
	private String email;
	private String id_comuna;
	private String id_giro;
	public Integer getId_cliente() {
		return id_cliente;
	}
	public void setId_cliente(Integer id_cliente) {
		this.id_cliente = id_cliente;
	}
	public String getNombre_cl() {
		return nombre_cl;
	}
	public void setNombre_cl(String nombre_cl) {
		this.nombre_cl = nombre_cl;
	}
	public String getDireccion() {
		return direccion;
	}
	public void setDireccion(String direccion) {
		this.direccion = direccion;
	}
	public Integer getTelefono() {
		return telefono;
	}
	public void setTelefono(Integer telefono) {
		this.telefono = telefono;
	}
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public String getId_comuna() {
		return id_comuna;
	}
	public void setId_comuna(String id_comuna) {
		this.id_comuna = id_comuna;
	}
	public String getId_giro() {
		return id_giro;
	}
	public void setId_giro(String id_giro) {
		this.id_giro = id_giro;
	}
	
}
