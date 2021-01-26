package dev.sys.model.dao;

import java.util.List;

import dev.sys.model.dto.AA_ProveedorDTO;

public interface AA_ProveedorDAO {

	public List<AA_ProveedorDTO> list();
	public AA_ProveedorDTO get(String id_proveedor);
	public int insert(AA_ProveedorDTO aa_proveedorDTO);
	public int update(AA_ProveedorDTO aa_proveedorDTO);
	public int delete(String id_proveedor);
}
