package dev.sys.model.dao;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import dev.sys.model.dto.AA_ProveedorDTO;

@Repository
@Transactional
public class AA_ProveedorDAOImpl implements AA_ProveedorDAO{
	
	private String list = "SELECT * FROM aa_proveedor ORDER BY id_proveedor";
	private String select = "SELECT * FROM aa_proveedor WHERE id_proveedor=?";
	private String insert = "INSERT INTO aa_proveedor VALUES (?,?,?,?,?,?,?,?,?,?)";
	private String update = "UPDATE aa_proveedor SET id_proveedor=?, nombre_proveedor=?, id_giro=?, contacto=?, email=?, direccion=?, "+
							"id_comuna=?, id_reg=?, id_pais=?, id_tproveedor WHERE id_proveedor=?";
	private String delete = "DELETE aa_proveedor WHERE id_proveedor=?";
	
	@Autowired
	private JdbcTemplate jdbcTemplate;
	public List<AA_ProveedorDTO> list() {
		List<AA_ProveedorDTO> listAA_ProveedorDTO = jdbcTemplate.query(list,
				BeanPropertyRowMapper.newInstance(AA_ProveedorDTO.class));
		return listAA_ProveedorDTO;
	}
	@Override
	public AA_ProveedorDTO get(String id_proveedor) {
	    Object[] args = {id_proveedor};
	    AA_ProveedorDTO aa_proveedorDTO;
	    
	    try {
	    	aa_proveedorDTO = jdbcTemplate.queryForObject(select,args,
	    		BeanPropertyRowMapper.newInstance(AA_ProveedorDTO.class));
	    } catch (EmptyResultDataAccessException e) {
	    	aa_proveedorDTO=null;
	    	e.printStackTrace();
	    } catch (Exception e) {
	    	aa_proveedorDTO=null;
	    	e.printStackTrace();
	    }
	    return aa_proveedorDTO;
	}
	@Override
	public int insert(AA_ProveedorDTO aa_proveedorDTO) {
		int rows = 0;
	    Object[] args = {
	    		aa_proveedorDTO.getId_proveedor(),
	    		aa_proveedorDTO.getNombre_proveedor(),
	    		aa_proveedorDTO.getId_giro(),
	    		aa_proveedorDTO.getContacto(),
	    		aa_proveedorDTO.getEmail(),
	    		aa_proveedorDTO.getDireccion(),
	    		aa_proveedorDTO.getId_comuna(),
	    		aa_proveedorDTO.getId_reg(),
	    		aa_proveedorDTO.getId_pais(),
	    		aa_proveedorDTO.getId_tproveedor()
	    		};
	    try {
			rows = jdbcTemplate.update(insert, args);	
	    } catch (Exception e) {
	    	e.printStackTrace();
	    }
	    return rows;
	}
	@Override
	public int update(AA_ProveedorDTO aa_proveedorDTO) {
		int rows = 0;
	    Object[] args = {
	    		aa_proveedorDTO.getId_proveedor(),
	    		aa_proveedorDTO.getNombre_proveedor(),
	    		aa_proveedorDTO.getId_giro(),
	    		aa_proveedorDTO.getContacto(),
	    		aa_proveedorDTO.getEmail(),
	    		aa_proveedorDTO.getDireccion(),
	    		aa_proveedorDTO.getId_comuna(),
	    		aa_proveedorDTO.getId_reg(),
	    		aa_proveedorDTO.getId_pais(),
	    		aa_proveedorDTO.getId_tproveedor()
	    		};
	    try {
			rows = jdbcTemplate.update(update, args);	
	    } catch (Exception e) {
	    	e.printStackTrace();
	    }
	    return rows;
	}
	@Override
	public int delete(String id_proveedor) {
		int rows = 0;
	    Object[] args = {id_proveedor};
	    try {
			rows = jdbcTemplate.update(delete, args);	
	    } catch (Exception e) {
	    	e.printStackTrace();
	    }
	    return rows;
	}

}
