package dev.sys.model.dao;

import java.sql.Types;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.BeanPropertyRowMapper;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import dev.sys.model.dao.UsersDAO;
import dev.sys.model.dto.UsersDTO;



@Repository
public class UsersDAOImpl implements UsersDAO{
	private String insertUsers="INSERT INTO users (username,password,enabled) VALUES(username = ?, password =? , enabled =?)";
	private String selectUsers="SELECT username FROM users WHERE user_id= ?";
	private String updateUsers="UPDATE users SET username= username, password= ?, enabled= ? WHERE user_id = ?";
	private String deleteUsers="DELETE FROM users WHERE user_id= ?";
	private String listUsers="SELECT * FROM users";
	
	
	private String insertRoles="INSERT INTO users_rol (users__user_id, rol__rol_id) "
			+ "VALUES("
			+ "(Select u.user_id from users u where u.username=?) "
			+ ",(Select r.rol_id from rol r where r.rol= ?)"
			+ ")";
			
		
		private String selectRoles="SELECT username FROM users WHERE user_id= ?";

	
	@Autowired
	private JdbcTemplate jdbcTemplate;
	
	@Autowired 
	NamedParameterJdbcTemplate namedParameterJdbcTemplate;
	

	@Override
	public int insertUsers(UsersDTO usersDTO) {
		int rows =0;
		
		try {
		
	
			MapSqlParameterSource params =new MapSqlParameterSource();
		
			params.addValue("username", usersDTO.getUsername(), Types.VARCHAR);
			params.addValue("password", usersDTO.getPassword(), Types.VARCHAR); 
			params.addValue("enabled", usersDTO.isEnabled(),Types.BOOLEAN);
			
			rows = namedParameterJdbcTemplate.update(insertUsers, params);
			
				
			} catch (Exception e) {
				e.printStackTrace();
			}
		
		return rows;
	}

	@Override
	public UsersDTO getUsers(int user_id) {
		Object args[]= {user_id};
		UsersDTO usersDTO;
		try {
			usersDTO= jdbcTemplate.queryForObject(selectUsers, args, BeanPropertyRowMapper.newInstance(UsersDTO.class));
			
		} catch (Exception e) {
			usersDTO=null;
			e.printStackTrace();
		}
		return usersDTO; 
	}
	
	@Override
	public int updateUsers(UsersDTO usersDTO) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public int deleteUsers(int user_id) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public List<UsersDTO> listUsers() {
		List<UsersDTO> listusers= jdbcTemplate.query(listUsers, BeanPropertyRowMapper.newInstance(UsersDTO.class));
		return listusers;
		
	}

	@Override
	public int insertRol(UsersDTO usersDTO) {
int rows =0;
		
		try {
		
	
			MapSqlParameterSource params =new MapSqlParameterSource();

			params.addValue("username", usersDTO.getUsername(), Types.VARCHAR);
			params.addValue("rol", usersDTO.getRol(), Types.VARCHAR);
		
			
			rows = namedParameterJdbcTemplate.update(insertRoles, params);
			
				
			} catch (Exception e) {
				e.printStackTrace();
			}
		
		return rows;
	}
	

	@Override
	public UsersDTO getRol(int rol_id) {
		Object args[]= {rol_id};
		UsersDTO usersDTO;
		try {
			usersDTO= jdbcTemplate.queryForObject(selectRoles, args, BeanPropertyRowMapper.newInstance(UsersDTO.class));
			
		} catch (Exception e) {
			usersDTO=null;
			e.printStackTrace();
		}
		return usersDTO; 
	}

	@Override
	public int updateRol(UsersDTO usersDTO) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public int deleteRol(int rol_id) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public List<UsersDTO> listRoles() {
		// TODO Auto-generated method stub
		return null;
	}

}
