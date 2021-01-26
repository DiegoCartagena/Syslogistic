package dev.sys.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import dev.sys.model.dao.BLDAO;
import dev.sys.model.dto.BLDTO;

@Service
public class BLServiceImpl implements BLService {

	//hacemos uso de la interfaz SalesDAO
	@Autowired
	BLDAO blDAO; 
	
	public BLServiceImpl() {
		 
	}

	//implementamos método lista.Se implementa el método definido en la interfaz.
	public List<BLDTO> list(){
		return blDAO.list();
	}

	@Override
	public int insert(BLDTO blDTO) {
		return blDAO.insert(blDTO);
	}

	@Override
	public BLDTO get(int Id_bl) {
	return blDAO.get(Id_bl);
	
	}

	@Override
	public int update(BLDTO blDTO) {
	return blDAO.update(blDTO);
	}

	@Override
	public int delete(int Id_bl) {
		return blDAO.delete(Id_bl);
	}
	
}
