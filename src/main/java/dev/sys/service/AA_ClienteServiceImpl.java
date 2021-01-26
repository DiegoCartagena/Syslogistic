package dev.sys.service;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import dev.sys.model.dao.AA_ClienteDAO;
import dev.sys.model.dto.AA_ClienteDTO;

@Service
public class AA_ClienteServiceImpl implements AA_ClienteService{
	@Autowired
	AA_ClienteDAO aa_clienteDAO;
	@Override
	public List<AA_ClienteDTO> list(){
		return aa_clienteDAO.list();
	}
	@Override
	public AA_ClienteDTO get(String id_cliente) {
		return aa_clienteDAO.get(id_cliente);
	}
	@Override
	public int delete(String id_cliente) {
		return aa_clienteDAO.delete(id_cliente);	
	}
	@Override
	public int insert(AA_ClienteDTO aa_clienteDTO) {
		return aa_clienteDAO.insert(aa_clienteDTO);
	}
	@Override
	public int update(AA_ClienteDTO aa_clienteDTO) {
		return aa_clienteDAO.update(aa_clienteDTO);
	}
}
