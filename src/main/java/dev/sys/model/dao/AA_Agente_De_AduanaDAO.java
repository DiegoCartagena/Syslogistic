package dev.sys.model.dao;
import java.util.List;
import dev.sys.model.dto.AA_Agente_De_AduanaDTO;

public interface AA_Agente_De_AduanaDAO {
	
	public List<AA_Agente_De_AduanaDTO> list();
	public AA_Agente_De_AduanaDTO get(String id_agente);
	public int insert(AA_Agente_De_AduanaDTO aa_agente_de_aduanaDTO);
	public int update(AA_Agente_De_AduanaDTO aa_agente_de_aduanaDTO);
	public int delete(String id_agente);
}
