package dev.sys.service;

import java.util.List;

import dev.sys.model.dto.BLDTO;

public interface BLService {
		public int insert(BLDTO blDTO); //Es tipo int debido a que la operación devuelve la cantidad de filas modificadas, en este caso queremos realizar sólo una modificacion. Recibe un dato tipo SalesDTO con nombre SalesDTO
		public BLDTO get(int Id_bl); //como es un read, vamos a obtener un dato de SalesDTO, un sólo sale y lo manejamos a nivel DTO,
		public int update(BLDTO blDTO); //recibe un dato tipo SalesDTO con nombre SalesDTO
		public int delete(int id);//
		public List<BLDTO> list();
		
}

