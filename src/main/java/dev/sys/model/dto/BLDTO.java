package dev.sys.model.dto;

import java.sql.Date;

public class BLDTO {
 // ocupamos la clase Integer, porque JDBC template cuando el dato es nulo y nativo de Java, se cae. 	
private Integer Id_bl; 
private String Nombre_nave; 
private int Num_sello; 
private String Consignatario;
private String Consignante; 
private int Peso; 
private int Vol_cubico; 
private String Mercaderia; 
private String Tipo_carga; 
private String Fecha_salida; 
private String Fecha_arribo; 
private int Unidades;
private String Carga; 
private String Incoterms; 
private String Pais; 
private String Documentacion;

public BLDTO() {
	super();
}
public BLDTO(Integer id_bl, String nombre_nave, int num_sello, String consignatario, String consignante, int peso,
		int vol_cubico, String mercaderia, String tipo_carga, String fecha_salida, String fecha_arribo, int unidades,
		String carga, String incoterms, String pais, String documentacion) {
	super();
	Id_bl = id_bl;
	Nombre_nave = nombre_nave;
	Num_sello = num_sello;
	Consignatario = consignatario;
	Consignante = consignante;
	Peso = peso;
	Vol_cubico = vol_cubico;
	Mercaderia = mercaderia;
	Tipo_carga = tipo_carga;
	Fecha_salida = fecha_salida;
	Fecha_arribo = fecha_arribo;
	Unidades = unidades;
	Carga = carga;
	Incoterms = incoterms;
	Pais = pais;
	Documentacion = documentacion;
}
public Integer getId_bl() {
	return Id_bl;
}
public void setId_bl(Integer id_bl) {
	Id_bl = id_bl;
}
public String getNombre_nave() {
	return Nombre_nave;
}
public void setNombre_nave(String nombre_nave) {
	Nombre_nave = nombre_nave;
}
public int getNum_sello() {
	return Num_sello;
}
public void setNum_sello(int num_sello) {
	Num_sello = num_sello;
}
public String getConsignatario() {
	return Consignatario;
}
public void setConsignatario(String consignatario) {
	Consignatario = consignatario;
}
public String getConsignante() {
	return Consignante;
}
public void setConsignante(String consignante) {
	Consignante = consignante;
}
public int getPeso() {
	return Peso;
}
public void setPeso(int peso) {
	Peso = peso;
}
public int getVol_cubico() {
	return Vol_cubico;
}
public void setVol_cubico(int vol_cubico) {
	Vol_cubico = vol_cubico;
}
public String getMercaderia() {
	return Mercaderia;
}
public void setMercaderia(String mercaderia) {
	Mercaderia = mercaderia;
}
public String getTipo_carga() {
	return Tipo_carga;
}
public void setTipo_carga(String tipo_carga) {
	Tipo_carga = tipo_carga;
}
public String getFecha_salida() {
	return Fecha_salida;
}
public void setFecha_salida(String fecha_salida) {
	Fecha_salida = fecha_salida;
}
public String getFecha_arribo() {
	return Fecha_arribo;
}
public void setFecha_arribo(String fecha_arribo) {
	Fecha_arribo = fecha_arribo;
}
public int getUnidades() {
	return Unidades;
}
public void setUnidades(int unidades) {
	Unidades = unidades;
}
public String getCarga() {
	return Carga;
}
public void setCarga(String carga) {
	Carga = carga;
}
public String getIncoterms() {
	return Incoterms;
}
public void setIncoterms(String incoterms) {
	Incoterms = incoterms;
}
public String getPais() {
	return Pais;
}
public void setPais(String pais) {
	Pais = pais;
}
public String getDocumentacion() {
	return Documentacion;
}
public void setDocumentacion(String documentacion) {
	Documentacion = documentacion;
}




}

