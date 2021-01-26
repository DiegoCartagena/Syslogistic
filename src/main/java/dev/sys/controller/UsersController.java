package dev.sys.controller;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import dev.sys.model.dto.UsersDTO;
import dev.sys.service.UsersService;

@Controller
@RequestMapping(value="/User") //todo lo que tenga sales --direcciona a esta clase.
public class UsersController {
	
	@Autowired
	UsersService usersService;

	@RequestMapping(value="/list")
	public @ResponseBody List<UsersDTO> ajaxList(HttpServletRequest req,HttpServletResponse res){
		return usersService.listUsers();
	}
	
	@RequestMapping(value="/get")
	public @ResponseBody UsersDTO ajaxGet(HttpServletRequest req,HttpServletResponse res){
		return usersService.getUsers(Integer.parseInt(req.getParameter("user_id")));
	}
	
	@RequestMapping(value="/insert")
	public @ResponseBody int ajaxInsert(HttpServletRequest req,HttpServletResponse res){
	
		int rows=0;
		String requestData;
		try {
			requestData = req.getReader().lines().collect(Collectors.joining());
			
			//cuando mandamos fecha desde web a controller, nos manda la fecha de cÃ³mo estÃ¡ en el cliente, por lo tanto lo dejamos como formato de java.sql
			
			
			Gson gson=new GsonBuilder().setDateFormat("yyyy-MM-dd").serializeNulls().create();
				
			//transforma la estructura de datos que viene del javascript para enviarla a DTO. viende de requestData y lo manda a SalesDTO.class
			UsersDTO users =gson.fromJson(requestData, UsersDTO.class);
		
			rows= usersService.insertUsers(users);
		} catch (IOException e) {
			e.printStackTrace();	
		}
		
		return rows;
		
		
	}
	
	@RequestMapping(value="/update")
	public @ResponseBody int ajaxUpdate(HttpServletRequest req,HttpServletResponse res){
		
		int rows=0;
		String requestData;
		try {
			requestData = req.getReader().lines().collect(Collectors.joining());
			Gson gson=new GsonBuilder().setDateFormat("yyyy-MM-dd").serializeNulls().create();
			UsersDTO users =gson.fromJson(requestData, UsersDTO.class);
			rows= usersService.updateUsers(users);
		} catch (IOException e) {
			e.printStackTrace();	
		}
		
		return rows;
	}
	
	@RequestMapping(value="/delete")
	public @ResponseBody int ajaxDelete(HttpServletRequest req,HttpServletResponse res){
		int rows=0;
		try {
			rows= usersService.deleteUsers(Integer.parseInt(req.getParameter("user_id")));
			System.out.println(req.getParameter("user_id"));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return rows;	
		}
}
