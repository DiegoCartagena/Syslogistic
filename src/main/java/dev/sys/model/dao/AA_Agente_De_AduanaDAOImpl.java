package dev.sys.model.dao;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import dev.sys.model.dto.AA_Agente_De_AduanaDTO;

@Repository
@Transactional
public class AA_Agente_De_AduanaDAOImpl implements AA_Agente_De_AduanaDAO {
	
	private String list = "SELECT * FROM aa_agente_de_aduana ORDER BY id_agente";
	private String select = "SELECT * FROM aa_agente_de_aduana WHERE id_agente=?";
	private String insert = "INSERT INTO aa_agente_de_aduana VALUES (?,?,?,?)";
	private String update = "UPDATE aa_agente_de_aduana SET id_agente=?, nombre_agente=?, pais=?, tipo_tlc=? "+
							"WHERE id_agente=?";
	private String delete = "DELETE aa_agente_de_aduana WHERE id_agente=?";
	
	@Autowired
	private JdbcTemplate jdbcTemplate;
	public List<AA_Agente_De_AduanaDTO> list() {
		List<AA_Agente_De_AduanaDTO> listAA_Agente_De_AduanaDTO = jdbcTemplate.query(list,
				BeanPropertyRowMapper.newInstance(AA_Agente_De_AduanaDTO.class));
		return listAA_Agente_De_AduanaDTO;
	}
	@Override
	public AA_Agente_De_AduanaDTO get(String id_agente) {
	    Object[] args = {id_agente};
	    AA_Agente_De_AduanaDTO aa_agente_de_aduanaDTO;
	    
	    try {
	    	aa_agente_de_aduanaDTO = jdbcTemplate.queryForObject(select,args,
	    		BeanPropertyRowMapper.newInstance(AA_Agente_De_AduanaDTO.class));
	    } catch (EmptyResultDataAccessException e) {
	    	aa_agente_de_aduanaDTO=null;
	    	e.printStackTrace();
	    } catch (Exception e) {
	    	aa_agente_de_aduanaDTO=null;
	    	e.printStackTrace();
	    }
	    return aa_agente_de_aduanaDTO;
	}
	@Override
	public int insert(AA_Agente_De_AduanaDTO aa_agente_de_aduanaDTO) {
		int rows = 0;
	    Object[] args = {
	    		aa_agente_de_aduanaDTO.getId_agente(),
	    		aa_agente_de_aduanaDTO.getNombre_agente(),
	    		aa_agente_de_aduanaDTO.getPais(),
	    		aa_agente_de_aduanaDTO.getTipo_tlc()
	    		};
	    try {
			rows = jdbcTemplate.update(insert, args);	
	    } catch (Exception e) {
	    	e.printStackTrace();
	    }
	    return rows;
	}
	@Override
	public int update(AA_Agente_De_AduanaDTO aa_agente_de_aduanaDTO) {
		int rows = 0;
	    Object[] args = {
	    		aa_agente_de_aduanaDTO.getId_agente(),
	    		aa_agente_de_aduanaDTO.getNombre_agente(),
	    		aa_agente_de_aduanaDTO.getPais(),
	    		aa_agente_de_aduanaDTO.getTipo_tlc()
	    		};
	    try {
			rows = jdbcTemplate.update(update, args);	
	    } catch (Exception e) {
	    	e.printStackTrace();
	    }
	    return rows;
	}
	@Override
	public int delete(String id_agente) {
		int rows = 0;
	    Object[] args = {id_agente};
	    try {
			rows = jdbcTemplate.update(delete, args);	
	    } catch (Exception e) {
	    	e.printStackTrace();
	    }
	    return rows;
	}

}
