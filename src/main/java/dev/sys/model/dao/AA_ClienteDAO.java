package dev.sys.model.dao;
import java.util.List;

import dev.sys.model.dto.AA_ClienteDTO;
public interface AA_ClienteDAO {
	
	public List<AA_ClienteDTO> list();
	public AA_ClienteDTO get(String id_cliente);
	public int insert(AA_ClienteDTO aa_clienteDTO);
	public int update(AA_ClienteDTO aa_clienteDTO);
	public int delete(String id_cliente);

}
