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

import dev.sys.model.dto.AA_ClienteDTO;
import dev.sys.service.AA_ClienteService;



@Controller
@RequestMapping(value="/Cliente")
public class ClienteController {
	
	@Autowired
	AA_ClienteService aa_clienteService;
	
	@RequestMapping(value="/list")
	public @ResponseBody List<AA_ClienteDTO> ajaxList(HttpServletRequest req, HttpServletResponse res) {
		List<AA_ClienteDTO> list = aa_clienteService.list();
		return list;
	}
	
	@RequestMapping(value="/get")
	public @ResponseBody AA_ClienteDTO ajaxGet(HttpServletRequest req, HttpServletResponse res) {
		AA_ClienteDTO c = aa_clienteService.get(req.getParameter("id_cliente"));
		return c;
	}
	
	@RequestMapping(value="/delete")
	public @ResponseBody int ajaxDelete(HttpServletRequest req, HttpServletResponse res) {
		int rows = aa_clienteService.delete(req.getParameter("id_cliente"));
		return rows;
	}
	
	@RequestMapping(value="/insert")
	public @ResponseBody int ajaxInsert(HttpServletRequest req, HttpServletResponse res) {
		int rows=0;
		try {
			String requestData = req.getReader().lines().collect(Collectors.joining());
			AA_ClienteDTO c = new Gson().fromJson(requestData, AA_ClienteDTO.class);
			rows = aa_clienteService.insert(c);
		} catch (IOException e) {
			e.printStackTrace();
		}
	
		return rows;
	}
	
	@RequestMapping(value="/update")
	public @ResponseBody int ajaxUpdate(HttpServletRequest req, HttpServletResponse res) {
		int rows=0;
		try {
			String requestData = req.getReader().lines().collect(Collectors.joining());
			AA_ClienteDTO c = new Gson().fromJson(requestData, AA_ClienteDTO.class);
			rows = aa_clienteService.update(c);
		} catch (IOException e) {
			e.printStackTrace();
		}
	
		return rows;
	}

}
