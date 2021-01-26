package dev.sys.model.dao;

import java.util.List;

import dev.sys.model.dto.BLDTO;

public interface BLDAO {


public int insert(BLDTO blDTO); //Es tipo int debido a que la operación devuelve la cantidad de filas modificadas, en este caso queremos realizar sólo una modificacion. Recibe un dato tipo SalesDTO con nombre SalesDTO
public BLDTO get(int id_bl); //como es un read, vamos a obtener un dato de SalesDTO, un sólo sale y lo manejamos a nivel DTO,
public int update(BLDTO blDTO); //recibe un dato tipo SalesDTO con nombre SalesDTO
public int delete(int id_bl);//
public List<BLDTO> list();// una lista de tipo SalesDTO llamado list
}
