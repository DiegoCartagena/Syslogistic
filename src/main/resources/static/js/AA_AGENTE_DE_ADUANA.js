function AA_AGENTE_DE_ADUANACONTROLLER(option){
	$("#msg").hide();
	$("#msg").removeClass("alert-success").addClass("alert-danger");
	var token = $("meta[name='_csrf']").attr("content");
	
	switch(option){
	
	case "list":
		$.ajax({
			type : "post",
			headers: {"X-CSRF-TOKEN": token},
		
			url : "/AA_AGENTE_DE_ADUANA/list",
			success : function(res){
				$("#aaTable").bootstrapTable('load',res);
				$("#aaTable tbody").on('click','tr', function(){
					$("#id_agente").val($(this).find("td:eq(0)").text());
					$("#nombre_agente").val($(this).find("td:eq(1)").text());
					$("#pais").val($(this).find("td:eq(2)").text());
					$("#tipo_tlc").val($(this).find("td:eq(3)").text());
					$("#myModal").click()
				});
				$("#myModal").modal({show:true})
			},
			error : function(){
				$("#msg").show();
				$("#msg").html("Error en la busqueda de BL");
			}
		});
		
		break;
		
	case "get":
		$.ajax({
			type : "post",
			headers: {"X-CSRF-TOKEN": token}, //send CSRF token in header
			url : "/AA_AGENTE_DE_ADUANA/get",
			data: "id_agente=" + $("#id_agente").val(),
			success : function(res){
				if (res== null || res==""){
					$("#msg").show();
					$("#msg").html("Registro no encontrado")
				}else{
					$("#id_agente").val(res.id_agente);
					$("#nombre_agente").val(res.nombre_agente);
					$("#pais").val(res.pais);
					$("#tipo_tlc").val(res.tipo_tlc);
					}
			},
			error : function(){
				$("#msg").show();
				$("#msg").html("Error en busqueda de BL");
			}
		});
		
		break;
		
	case "insert":
		var json = 
	{
			'id_agente' : $("#id_agente").val(),
			'nombre_agente' : $("#nombre_agente").val(),
			'pais' : $("#pais").val(),
			'tipo_tlc' : $("#tipo_tlc").val(),
	
	}
		var postData= JSON.stringify(json);
		
		$.ajax({
			type : "post",
			headers: {"X-CSRF-TOKEN": token}, //send CSRF token in header
			url : "/AA_AGENTE_DE_ADUANA/insert",
			data: postData,
			contentType : "application/json; charset=utf-8",
			dataType : "json",
			success : function(res){
				if (res== 1){
					$("#msg").removeClass("alert-danger").addClass("alert-success")
					$("#msg").show();
					$("#msg").html("Registro insertado correctamente")
				}else{
					$("#msg").show();
					$("#msg").html("Error al agregar registro")
				}
			},
			error : function(){
				$("#msg").show();
				$("#msg").html("Error al agregar registro");
			}
		});
		break;
		
	case "update":
		
		var json = 
	{
			'id_agente' : $("#id_agente").val(),
			'nombre_agente' : $("#nombre_agente").val(),
			'pais' : $("pais").val(),
			'tipo_tlc' : $("#tipo_tlc").val(),
	}
	
		var postData= JSON.stringify(json);
		
		$.ajax({
			type : "post",
			headers: {"X-CSRF-TOKEN": token}, //send CSRF token in header
			url : "/AA_AGENTE_DE_ADUANA/update",
			data: postData,
			contentType : "application/json; charset=utf-8",
			success : function(res){
				if (res== 1){
					$("#msg").removeClass("alert-danger").addClass("alert-success")
					$("#msg").show();
					$("#msg").html("Registro actualizado correctamente")
				}else{
					$("#msg").show();
					$("#msg").html("Error al actualizar registro")
				}
			},
			error : function(){
				$("#msg").show();
				$("#msg").html("Error al actualizar registro");
			}
		});
		
		break;
		
	case "delete":
		$.ajax({
			type : "post",
			headers: {"X-CSRF-TOKEN": token}, //send CSRF token in header
			url : "/AA_AGENTE_DE_ADUANA/delete",
			data: "id_agente=" + $("#id_agente").val(),
			success : function(res){
				if (res==1){
					$("#msg").removeClass("alert-danger").addClass("alert-success")
					$("#msg").show();
					$("#msg").html("Registro eliminado con exito")
				}else{
					$("#msg").show();
					$("#msg").html("Registro no se pudo eliminar ")
				}
			},
			error : function(){
				$("#msg").show();
				$("#msg").html("Error al eliminar");
			}
		});
		break;
		
		default:
			$("#msg").show();
			$("#msg").html("Opcion no valida");
	
	}
}