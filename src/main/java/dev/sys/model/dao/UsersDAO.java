package dev.sys.model.dao;

import java.util.List;

import dev.sys.model.dto.UsersDTO;

public interface UsersDAO {
 public int insertUsers(UsersDTO usersDTO);
 public UsersDTO getUsers(int user_id);
 public int updateUsers(UsersDTO usersDTO);
 public int deleteUsers(int user_id);
 public List<UsersDTO> listUsers();
 
 
 public int insertRol(UsersDTO usersDTO);
 public UsersDTO getRol(int rol_id);
 public int updateRol(UsersDTO usersDTO);
 public int deleteRol(int rol_id);
 public List<UsersDTO> listRoles();
}
