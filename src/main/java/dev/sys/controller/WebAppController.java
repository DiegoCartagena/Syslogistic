package dev.sys.controller;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Servlet implementation class WebAppController
 */
@Controller("/WebAppController")
public class WebAppController {
	
		@RequestMapping("/")
		public String getHome(){
			return "home";
		}
	
		@RequestMapping("/login")
		public String getLogin(){
			return "login";
		}
		
		@RequestMapping("/index")
		public String getIndex(){
			return "index";
		}
		@RequestMapping("/BL")
		public String getBL() {
			return "BL";
			
		}
		
		@RequestMapping("/403")
		public String get403(){
			return "403";
		}

		@RequestMapping("/User")
		public String getUser(){
			return "User";
		}
		
		@RequestMapping("/AA_AGENTE_DE_ADUANA")
		public String getAA_AGENTE_DE_ADUANA(){
			return "AA_AGENTE_DE_ADUANA";
		}
		
		@RequestMapping("/Cliente")
		public String getCliente(){
			return "Cliente";
		}
		
		@RequestMapping("/proveedor")
		public String getproveedor(){
			return "proveedor";
		}
		
		@RequestMapping("/Aprobado")
		public String getAprobado(){
			return "Aprobado";
		}

}
