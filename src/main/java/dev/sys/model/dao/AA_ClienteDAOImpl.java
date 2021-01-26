package dev.sys.model.dao;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import dev.sys.model.dto.AA_ClienteDTO;

@Repository
@Transactional
public class AA_ClienteDAOImpl implements AA_ClienteDAO{
	
	private String list = "SELECT * FROM aa_cliente ORDER BY id_cliente";
	private String select = "SELECT * FROM aa_cliente WHERE id_cliente=?";
	private String insert = "INSERT INTO aa_cliente VALUES (?,?,?,?,?,?,?)";
	private String update = "UPDATE aa_cliente SET id_cliente=?, nombre_cl=?, direccion=?, telefono=?, email=?"+
							"id_comuna=?, id_giro=? WHERE id_cliente=?";
	private String delete = "DELETE aa_cliente WHERE id_cliente=?";
	
	@Autowired
	private JdbcTemplate jdbcTemplate;
	public List<AA_ClienteDTO> list() {
		List<AA_ClienteDTO> listAA_ClienteDTO = jdbcTemplate.query(list,
				BeanPropertyRowMapper.newInstance(AA_ClienteDTO.class));
		return listAA_ClienteDTO;
	}
	@Override
	public AA_ClienteDTO get(String id_cliente) {
	    Object[] args = {id_cliente};
	    AA_ClienteDTO aa_clienteDTO;
	    
	    try {
	    	aa_clienteDTO = jdbcTemplate.queryForObject(select,args,
	    		BeanPropertyRowMapper.newInstance(AA_ClienteDTO.class));
	    } catch (EmptyResultDataAccessException e) {
	    	aa_clienteDTO=null;
	    	e.printStackTrace();
	    } catch (Exception e) {
	    	aa_clienteDTO=null;
	    	e.printStackTrace();
	    }
	    return aa_clienteDTO;
	}
	@Override
	public int insert(AA_ClienteDTO aa_clienteDTO) {
		int rows = 0;
	    Object[] args = {
	    		aa_clienteDTO.getId_cliente(),
	    		aa_clienteDTO.getNombre_cl(),
	    		aa_clienteDTO.getDireccion(),
	    		aa_clienteDTO.getTelefono(),
	    		aa_clienteDTO.getEmail(),
	    		aa_clienteDTO.getId_comuna(),
	    		aa_clienteDTO.getId_giro()
	    		};
	    try {
			rows = jdbcTemplate.update(insert, args);	
	    } catch (Exception e) {
	    	e.printStackTrace();
	    }
	    return rows;
	}
	@Override
	public int update(AA_ClienteDTO aa_clienteDTO) {
		int rows = 0;
	    Object[] args = {
	    		aa_clienteDTO.getId_cliente(),
	    		aa_clienteDTO.getNombre_cl(),
	    		aa_clienteDTO.getDireccion(),
	    		aa_clienteDTO.getTelefono(),
	    		aa_clienteDTO.getEmail(),
	    		aa_clienteDTO.getId_comuna(),
	    		aa_clienteDTO.getId_giro()
	    		};
	    try {
			rows = jdbcTemplate.update(update, args);	
	    } catch (Exception e) {
	    	e.printStackTrace();
	    }
	    return rows;
	}
	@Override
	public int delete(String id_cliente) {
		int rows = 0;
	    Object[] args = {id_cliente};
	    try {
			rows = jdbcTemplate.update(delete, args);	
	    } catch (Exception e) {
	    	e.printStackTrace();
	    }
	    return rows;
	}
}
