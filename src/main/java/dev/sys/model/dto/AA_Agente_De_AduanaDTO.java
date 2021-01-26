package dev.sys.model.dto;

public class AA_Agente_De_AduanaDTO {
	private Integer id_agente;
	private String nombre_agente;
	private String pais;
	private String tipo_tlc;
	
	public Integer getId_agente() {
		return id_agente;
	}
	public void setId_agente(Integer id_agente) {
		this.id_agente = id_agente;
	}
	public String getNombre_agente() {
		return nombre_agente;
	}
	public void setNombre_agente(String nombre_agente) {
		this.nombre_agente = nombre_agente;
	}
	public String getPais() {
		return pais;
	}
	public void setPais(String pais) {
		this.pais = pais;
	}
	public String getTipo_tlc() {
		return tipo_tlc;
	}
	public void setTipo_tlc(String tipo_tlc) {
		this.tipo_tlc = tipo_tlc;
	}
	
}
