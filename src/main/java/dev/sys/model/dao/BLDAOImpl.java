package dev.sys.model.dao;

import java.sql.PreparedStatement;
import java.sql.Types;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import dev.sys.model.dto.BLDTO;

@Repository
public class BLDAOImpl implements BLDAO {
	private String insert="INSERT INTO BL (Id_bl,Nombre_nave, Num_sello, Consignatario, Consignante, Peso, Vol_cubico, Mercaderia, Tipo_carga, Fecha_salida, Fecha_arribo, Unidades, Carga, Incoterms, Pais, Documentacion) VALUES(:Id_bl, :Nombre_nave, :Num_sello, :Consignatario, :Consignante, :Peso, :Vol_cubico, :Mercaderia, :Tipo_carga, :Fecha_salida, :Fecha_arribo, :Unidades, :Carga, :Incoterms, :Pais, :Documentacion)";
	private String select="SELECT * FROM BL WHERE Id_bl=?";
	private String update="UPDATE BL SET Id_bl= :Id_bl, Nombre_nave= :Nombre_nave, Num_sello= :Num_sello, Consignatario= :Consignatario, Consignante= :Consignante, Peso= :Peso, Vol_cubico= :Vol_cubico, Mercaderia= :Mercaderia, Tipo_carga= :Tipo_carga, Fecha_salida= :Fecha_salida, Fecha_arribo= :Fecha_arribo, Unidades= :Unidades, Carga= :Carga, Incoterms= :Incoterms, Pais= :Pais, Documentacion= :Documentacion  WHERE Id_bl= :Id_bl";
	private String delete="DELETE FROM BL WHERE Id_bl=?";
	private String list="SELECT * FROM BL";
	

	
	@Autowired
	private JdbcTemplate jdbcTemplate;
	
	@Autowired 
	NamedParameterJdbcTemplate namedParameterJdbcTemplate;
	

	@Override
	public int insert(BLDTO blDTO) {
		

	
		int rows =0;
	
		 
		try {
		
	
			MapSqlParameterSource params =new MapSqlParameterSource();
			
			params.addValue("Id_bl", blDTO.getId_bl(), Types.INTEGER);
			params.addValue("Nombre_nave", blDTO.getNombre_nave(), Types.VARCHAR);
			params.addValue("Num_sello", blDTO.getNum_sello(), Types.INTEGER);
			
			if (blDTO.getConsignatario() !=null) {
				params.addValue("Consignatario", blDTO.getConsignatario(), Types.VARCHAR);
			}else {
			params.addValue("Consignatario", blDTO.getConsignatario(), Types.NULL);
			}

			if (blDTO.getConsignante() !=null) {
				params.addValue("Consignante", blDTO.getConsignante(),Types.VARCHAR);
			}else {
				params.addValue("Consignante", blDTO.getConsignante(), Types.NULL);
			}
			
			if(blDTO.getPeso() != 0) {
				params.addValue("Peso", blDTO.getPeso(), Types.INTEGER);
			}else {
				params.addValue("Peso", blDTO.getPeso(), Types.NULL);
			}
			
			if(blDTO.getVol_cubico() != 0) {
				params.addValue("Vol_cubico", blDTO.getVol_cubico(), Types.INTEGER);
			}else {
				params.addValue("Vol_cubico", blDTO.getVol_cubico(), Types.NULL);
			}
			
			if(blDTO.getMercaderia() !=null) {
				params.addValue("Mercaderia", blDTO.getMercaderia(), Types.VARCHAR);
			}else {
				params.addValue("Mercaderia", blDTO.getMercaderia(), Types.NULL);
			}
			
			 if(blDTO.getTipo_carga() !=null) {
				 params.addValue("Tipo_carga", blDTO.getTipo_carga(), Types.VARCHAR);
			 }else {
				 params.addValue("Tipo_carga", blDTO.getTipo_carga(), Types.NULL);
			 }
			if(blDTO.getFecha_salida() !=null) {
				params.addValue("Fecha_salida", blDTO.getFecha_salida(), Types.VARCHAR);
			}else {
				params.addValue("Fecha_salida", blDTO.getFecha_salida(), Types.NULL);
			}
			
			if(blDTO.getFecha_arribo() !=null) {
				params.addValue("Fecha_arribo", blDTO.getFecha_arribo(),Types.VARCHAR);
			}else {
				params.addValue("Fecha_arribo", blDTO.getFecha_arribo(), Types.NULL);
			}
			
			if(blDTO.getUnidades() != 0) {
				params.addValue("Unidades", blDTO.getUnidades(), Types.VARCHAR);
			}else {
				params.addValue("Unidades",blDTO.getUnidades(), Types.NULL);
			}
			
			if(blDTO.getCarga() !=null) {
				params.addValue("Carga", blDTO.getCarga(), Types.VARCHAR);
			}else {
				params.addValue("Carga", blDTO.getCarga(), Types.NULL);
			} 
			 
			if(blDTO.getIncoterms() !=null) {
				 params.addValue("Incoterms", blDTO.getIncoterms(), Types.VARCHAR);
			}else {
				 params.addValue("Incoterms", blDTO.getIncoterms(), Types.NULL);
			}
			 
			if(blDTO.getPais() !=null) {
				 params.addValue("Pais", blDTO.getPais(), Types.VARCHAR);
			}else {
				 params.addValue("Pais", blDTO.getPais(), Types.NULL);
			}
			
			if(blDTO.getDocumentacion() !=null) {
				 params.addValue("Documentacion", blDTO.getDocumentacion(), Types.VARCHAR);
			}else {
				 params.addValue("Documentacion", blDTO.getDocumentacion(), Types.NULL);
			}
			rows = namedParameterJdbcTemplate.update(insert, params);
			
				
			} catch (Exception e) {
				e.printStackTrace();
			}
		
		return rows;
		
	}

	@Override
	public BLDTO get(int Id_bl) {
		Object args[]= {Id_bl};
		BLDTO blDTO;
		try {
			blDTO= jdbcTemplate.queryForObject(select, args, BeanPropertyRowMapper.newInstance(BLDTO.class));
			
		} catch (Exception e) {
			blDTO=null;
			e.printStackTrace();
		}
		return blDTO; 
	}

	@Override
	public int update(BLDTO blDTO) {
		int rows =0;
	
		MapSqlParameterSource params =new MapSqlParameterSource();
		
		params.addValue("Id_bl", blDTO.getId_bl(), Types.INTEGER);
		params.addValue("Nombre_nave", blDTO.getNombre_nave(), Types.VARCHAR);
		params.addValue("Num_sello", blDTO.getNum_sello(), Types.INTEGER);
		
		if (blDTO.getConsignatario() !=null) {
			params.addValue("Consignatario", blDTO.getConsignatario(), Types.VARCHAR);
		}else {
		params.addValue("Consignatario", blDTO.getConsignatario(), Types.NULL);
		}

		if (blDTO.getConsignante() !=null) {
			params.addValue("Consignante", blDTO.getConsignante(),Types.VARCHAR);
		}else {
			params.addValue("Consignante", blDTO.getConsignante(), Types.NULL);
		}
		
		if(blDTO.getPeso() != 0) {
			params.addValue("Peso", blDTO.getPeso(), Types.INTEGER);
		}else {
			params.addValue("Peso", blDTO.getPeso(), Types.NULL);
		}
		
		if(blDTO.getVol_cubico() != 0) {
			params.addValue("Vol_cubico", blDTO.getVol_cubico(), Types.INTEGER);
		}else {
			params.addValue("Vol_cubico", blDTO.getVol_cubico(), Types.NULL);
		}
		
		if(blDTO.getMercaderia() !=null) {
			params.addValue("Mercaderia", blDTO.getMercaderia(), Types.VARCHAR);
		}else {
			params.addValue("Mercaderia", blDTO.getMercaderia(), Types.NULL);
		}
		
		 if(blDTO.getTipo_carga() !=null) {
			 params.addValue("Tipo_carga", blDTO.getTipo_carga(), Types.VARCHAR);
		 }else {
			 params.addValue("Tipo_carga", blDTO.getTipo_carga(), Types.NULL);
		 }
		if(blDTO.getFecha_salida() !=null) {
			params.addValue("Fecha_salida", blDTO.getFecha_salida(), Types.VARCHAR);
		}else {
			params.addValue("Fecha_salida", blDTO.getFecha_salida(), Types.NULL);
		}
		
		if(blDTO.getFecha_arribo() !=null) {
			params.addValue("Fecha_arribo", blDTO.getFecha_arribo(),Types.VARCHAR);
		}else {
			params.addValue("Fecha_arribo", blDTO.getFecha_arribo(), Types.NULL);
		}
		
		if(blDTO.getUnidades() != 0) {
			params.addValue("Unidades", blDTO.getUnidades(), Types.VARCHAR);
		}else {
			params.addValue("Unidades",blDTO.getUnidades(), Types.NULL);
		}
		
		if(blDTO.getCarga() !=null) {
			params.addValue("Carga", blDTO.getCarga(), Types.VARCHAR);
		}else {
			params.addValue("Carga", blDTO.getCarga(), Types.NULL);
		} 
		 
		if(blDTO.getIncoterms() !=null) {
			 params.addValue("Incoterms", blDTO.getIncoterms(), Types.VARCHAR);
		}else {
			 params.addValue("Incoterms", blDTO.getIncoterms(), Types.NULL);
		}
		 
		if(blDTO.getPais() !=null) {
			 params.addValue("Pais", blDTO.getPais(), Types.VARCHAR);
		}else {
			 params.addValue("Pais", blDTO.getPais(), Types.NULL);
		}
		
		if(blDTO.getDocumentacion() !=null) {
			 params.addValue("Documentacion", blDTO.getDocumentacion(), Types.VARCHAR);
		}else {
			 params.addValue("Documentacion", blDTO.getDocumentacion(), Types.NULL);
		}
	
		
			try {
				
				rows = namedParameterJdbcTemplate.update(update, params);
				
					
			 } catch (Exception e) {
					e.printStackTrace();
				
				}
				 	
			return rows;
	}
	


	@Override
	public int delete(int id) {
	int rows=0;
	
		Object args[]= {id};
	try {
			rows= jdbcTemplate.update(delete,args);
			
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		return rows; 
	}

	@Override
	public List<BLDTO> list() {
	//devuelve un tipo List SalesDTO
	//vamos a hacer un mapeo para la fila. Se ocupa el rowMapper -->se ocupa clase BeanPropertyRowMapper, convierte una clase a un objeto, así
	//jdbcTemplate sabe que tiene que devolver un dato tipo SalesDTO
	//como esta consulta no recibe argumentos dado que es un Select * ; por lo tanto se quita el "args".	
		List<BLDTO> listbl= jdbcTemplate.query(list, BeanPropertyRowMapper.newInstance(BLDTO.class));
		return listbl;
	}

}
