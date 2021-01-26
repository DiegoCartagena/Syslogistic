package dev.sys.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestMapping;

import dev.sys.model.dao.UsersDAO;
import dev.sys.model.dto.UsersDTO;

@Service

public class UsersServiceImpl implements UsersService {
	
	//hacemos uso de la interfaz UsersDAO
	@Autowired
	UsersDAO usersDAO;

	@Override
	public int insertUsers(UsersDTO usersDTO) {
		return usersDAO.insertUsers(usersDTO);
	}

	@Override
	public UsersDTO getUsers(int user_id) {
		return usersDAO.getUsers(user_id);
	}

	@Override
	public int updateUsers(UsersDTO usersDTO) {
		return usersDAO.updateUsers(usersDTO);
	}

	@Override
	public int deleteUsers(int user_id) {
		return usersDAO.deleteUsers(user_id);
	}

	@Override
	public List<UsersDTO> listUsers() {
		return usersDAO.listUsers();
	}

	@Override
	public int insertRol(UsersDTO usersDTO) {
		return usersDAO.insertRol(usersDTO);
	}

	@Override
	public UsersDTO getRol(int rol_id) {
		return usersDAO.getRol(rol_id);
	}

	@Override
	public int updateRol(UsersDTO usersDTO) {
		return usersDAO.updateRol(usersDTO);
	}

	@Override
	public int deleteRol(int rol_id) {
		return usersDAO.deleteRol(rol_id);
		
	}

	@Override
	public List<UsersDTO> listRol() {
		return usersDAO.listRoles();
	}
	


	
	  
}
